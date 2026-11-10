"""Cards a later full pass does not find again are retired ("no longer seen"),
come back if the issue returns, and are never retired on an incomplete pass."""
import asyncio

import httpx

from eeaao import db
from eeaao.bots import runner
from tests.test_headers import GOOD_HEADERS, store
from tests.test_recon import PROGRAM, DbTestCase

URL = "https://www.example.com/"
BARE = [("Content-Type", "text/html"), ("Server", "nginx/1.18.0")]


def run(pid, department="headers"):
    def offline(request):
        raise AssertionError("no requests expected")

    async def go():
        run_id = runner.start(db.get_program(pid), department, None, {},
                              transport=httpx.MockTransport(offline))
        await runner.wait(run_id)
        return run_id
    run_id = asyncio.run(go())
    assert db.get_run(run_id)["status"] == "done"
    return [e["message"] for e in db.list_events(run_id)]


def age(pid):
    """Pretend every card was last seen long ago (timestamps have 1 s resolution)."""
    with db.connect() as conn:
        conn.execute("UPDATE findings SET last_seen = '2020-01-01T00:00:00+00:00' "
                     "WHERE program_id = ?", (pid,))


def statuses(pid):
    return {f["type"]: f["status"] for f in db.list_findings(pid, "finding")}


class RetireTests(DbTestCase):
    def test_fixed_issue_is_retired_and_returns(self):
        pid = db.create_program(PROGRAM)
        store(pid, URL, BARE, "<p>home</p>")
        run(pid)
        before = statuses(pid)
        self.assertEqual(before["missing_csp"], "new")
        self.assertEqual(before["version_disclosure"], "new")
        # the user reviewed one card: that decision must survive
        reviewed = next(f for f in db.list_findings(pid, "finding") if f["type"] == "missing_xcto")
        db.set_finding_status(reviewed["id"], "reviewed")

        # the site is fixed, Recon stores the new response, Headers runs again
        age(pid)
        store(pid, URL, GOOD_HEADERS, "<p>home</p>")
        events = run(pid)
        after = statuses(pid)
        self.assertEqual(after["missing_csp"], "stale")
        self.assertEqual(after["version_disclosure"], "stale")
        self.assertEqual(after["missing_xcto"], "reviewed")
        self.assertTrue(any("no longer seen" in e for e in events))

        # the problem comes back: the same card returns, it is not duplicated
        age(pid)
        store(pid, URL, BARE, "<p>home</p>")
        run(pid)
        again = db.list_findings(pid, "finding")
        self.assertEqual(statuses(pid)["missing_csp"], "new")
        self.assertEqual(sum(1 for f in again if f["type"] == "missing_csp"), 1)

    def test_incomplete_pass_retires_nothing(self):
        pid = db.create_program(PROGRAM)
        store(pid, URL, BARE, "<p>home</p>")
        run(pid)
        age(pid)
        with db.connect() as conn:  # the stored responses are gone (e.g. data cleared)
            conn.execute("DELETE FROM responses WHERE program_id = ?", (pid,))
        run(pid)
        self.assertTrue(all(s == "new" for s in statuses(pid).values()), statuses(pid))

    def test_other_bots_cards_are_untouched(self):
        pid = db.create_program(PROGRAM)
        store(pid, URL, BARE + [("Set-Cookie", "sessionid=abcdef1234567890; Path=/")], "<p>x</p>")
        run(pid, "cookies")
        age(pid)
        run(pid, "headers")  # a different department must not retire cookie cards
        cookies = [f for f in db.list_findings(pid, "finding") if f["department"] == "cookies"]
        self.assertTrue(cookies)
        self.assertTrue(all(f["status"] == "new" for f in cookies))

    def test_version_strings_are_grouped_across_sites(self):
        pid = db.create_program(PROGRAM)
        for host in ("a", "b", "c"):
            store(pid, f"https://{host}.example.com/robots.txt",
                  [("Content-Type", "text/plain"), ("Server", "Microsoft-IIS/10.0")], "ok")
        run(pid)
        cards = [f for f in db.list_findings(pid, "finding") if f["type"] == "version_disclosure"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["title"], "Server reveals 'Microsoft-IIS/10.0' on 3 sites")
        self.assertEqual(len(cards[0]["evidence"]["sites"]), 3)
