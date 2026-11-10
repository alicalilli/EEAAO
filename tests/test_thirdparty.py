"""Third-party links: registry (RDAP) and platform API checks, never the linked sites."""
import asyncio
import unittest

import httpx

from eeaao import db
from eeaao.bots.net import SourceClient
from eeaao.bots.thirdparty import registrable, social_handle
from tests.test_more_departments import run_dept
from tests.test_recon import PROGRAM, DbTestCase

PAGE = {"https://www.example.com/": 1}
BOOTSTRAP = {"services": [
    [["com", "net"], ["https://rdap.registry-a.test/"]],
    [["org"], ["https://rdap.registry-b.test/rdap"]],
    [["io"], ["http://plain.registry-c.test/", "https://rdap.registry-c.test/"]],
]}
ALLOWED = {"data.iana.org", "rdap.registry-a.test", "rdap.registry-b.test",
           "rdap.registry-c.test", "api.github.com", "gitlab.com"}


def handler(request):
    host, path = request.url.host, request.url.path
    assert host in ALLOWED, f"contacted {host}"
    if host == "data.iana.org":
        return httpx.Response(200, json=BOOTSTRAP)
    if host.startswith("rdap."):
        domain = path.rsplit("/", 1)[-1]
        return {
            "deadvendor.com": httpx.Response(404),
            "oldpartner.net": httpx.Response(200, json={"status": ["pending delete"]}),
            "expiredshop.org": httpx.Response(200, json={
                "status": ["active"],
                "events": [{"eventAction": "expiration", "eventDate": "2020-01-01T00:00:00Z"}]}),
            "fine.io": httpx.Response(200, json={
                "status": ["active"],
                "events": [{"eventAction": "expiration", "eventDate": "2099-01-01T00:00:00Z"}]}),
        }[domain]
    if host == "api.github.com":
        return httpx.Response(200 if path.endswith("/examplecorp") else 404, json={})
    if host == "gitlab.com":
        if path == "/api/v4/users":
            return httpx.Response(200, json=[])
        return httpx.Response(404, json={"message": "404 Group Not Found"})
    raise AssertionError(request.url)


class ThirdPartyTests(DbTestCase):
    def seed(self):
        pid = db.create_program(PROGRAM)
        links = {
            "https://cdn.deadvendor.com/widget.js": "script",
            "https://oldpartner.net/": "a",
            "https://expiredshop.org/x": "a",
            "https://fine.io/": "a",
            "https://blog.example.co.uk/": "a",
            "https://admin.example.com/": "a",
            "https://www.google.com/maps": "a",
            "https://github.com/examplecorp": "a",
            "https://github.com/ghostcorp": "a",
            "https://github.com/features": "a",
            "https://gitlab.com/oldteam": "a",
            "https://twitter.com/examplecorp": "a",
            "https://twitter.com/intent/tweet?text=hi": "a",
        }
        assets = [("external", url, {"kind": tag, "pages": PAGE}) for url, tag in links.items()]
        # linked only from an out-of-scope page: ignored
        assets.append(("external", "https://onlyadmin.com/",
                       {"kind": "a", "pages": {"https://admin.example.com/": 1}}))
        db.upsert_assets(pid, assets)
        return pid

    def test_run(self):
        pid = self.seed()
        _, calls = run_dept(pid, "thirdparty", handler)
        hosts = {c.url.host for c in calls}
        self.assertTrue(hosts <= ALLOWED, hosts)
        self.assertNotIn("plain.registry-c.test", hosts)  # https server preferred
        rdap = sorted(c.url.path.rsplit("/", 1)[-1] for c in calls if c.url.host.startswith("rdap."))
        self.assertEqual(rdap, ["deadvendor.com", "expiredshop.org", "fine.io", "oldpartner.net"])

        findings = db.list_findings(pid, "finding")
        broken = {f["evidence"]["domain"]: (f["severity"], f["evidence"]["registry_state"])
                  for f in findings if f["type"] == "broken_link_expired_domain"}
        self.assertEqual(broken, {"deadvendor.com": ("high", "not registered"),
                                  "oldpartner.net": ("low", "being deleted"),
                                  "expiredshop.org": ("info", "expired")})
        script = next(f for f in findings if f["evidence"].get("domain") == "deadvendor.com")
        self.assertIn("loads a script from", script["title"])

        social = {f["title"] for f in findings if f["type"] == "social_handle_unclaimed"}
        self.assertEqual(social, {"Linked GitHub account 'ghostcorp' does not exist",
                                  "Linked GitLab account 'oldteam' does not exist"})
        inventory = {a["value"]: a["data"]["status"] for a in db.get_assets(pid, "social")}
        self.assertEqual(inventory["https://github.com/examplecorp"], "exists")
        self.assertTrue(inventory["https://twitter.com/examplecorp"].startswith("not checked"))
        self.assertNotIn("https://github.com/features", inventory)
        domains = {a["value"]: a["data"] for a in db.get_assets(pid, "linkdomain")}
        self.assertIn("no RDAP", domains["example.co.uk"]["registry"])
        self.assertNotIn("example.com", domains)
        self.assertNotIn("onlyadmin.com", domains)

    def test_source_client_refuses_unknown_hosts(self):
        async def go():
            client = SourceClient(1, None, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
            with self.assertRaises(ValueError):
                await client.get("https://deadvendor.com/", "test")
            client.allow_registry("rdap.registry-a.test")
            with self.assertRaises(ValueError):
                await client.get("http://rdap.registry-a.test/domain/x.com", "test")  # not https
            await client.close()
        asyncio.run(go())


class HelperTests(unittest.TestCase):
    def test_registrable(self):
        self.assertEqual(registrable("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable("cdn.deadvendor.com"), "deadvendor.com")
        self.assertIsNone(registrable("203.0.113.5"))

    def test_social(self):
        self.assertEqual(social_handle("https://www.linkedin.com/company/acme/"), ("LinkedIn", "company/acme"))
        self.assertEqual(social_handle("https://x.com/acme_inc"), ("X (Twitter)", "acme_inc"))
        self.assertEqual(social_handle("https://www.youtube.com/@acme"), ("YouTube", "@acme"))
        self.assertIsNone(social_handle("https://www.facebook.com/sharer/sharer.php?u=x"))
        self.assertIsNone(social_handle("https://example.com/acme"))


if __name__ == "__main__":
    unittest.main()
