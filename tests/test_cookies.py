"""Cookies department, and storage of redirect responses that set cookies."""
import asyncio
import unittest

import httpx

from eeaao import db
from eeaao.bots import runner
from eeaao.bots.base import BotContext, RunShared
from eeaao.bots.cookies import parse_set_cookie
from eeaao.bots.net import TargetClient
from eeaao.bots.stored import Page
from eeaao.scope import ScopeGuard
from tests.test_headers import store
from tests.test_recon import PROGRAM, DbTestCase

RANDOM = "Zx9qT2mLp8Vb4Rk7Wc1Nf6Hy3Jd5Gs0A"


class CookieRunTests(DbTestCase):
    def run_cookies(self, program_id):
        calls = []

        def offline(request):
            calls.append(request)
            raise AssertionError("the Cookies department must not send requests")

        async def go():
            run_id = runner.start(db.get_program(program_id), "cookies", None, {},
                                  transport=httpx.MockTransport(offline))
            await runner.wait(run_id)
            return run_id
        return asyncio.run(go()), calls

    def seed(self):
        pid = db.create_program(PROGRAM)
        html = [("Content-Type", "text/html")]
        store(pid, "https://app.example.com/", html + [
            ("Set-Cookie", "sessionid=abcdef1234567890; Path=/"),
            ("Set-Cookie", "_ga=GA1.2.123.456; Domain=.example.com; Path=/"),
            ("Set-Cookie", "csrftoken=xyz123456789; Path=/; Secure; SameSite=Lax"),
            # an anti-CSRF cookie without flags: not a session cookie, never flagged
            ("Set-Cookie", "XSRF-TOKEN=k3j4h5g6f7d8a9s0d1f2; Path=/"),
            ("Set-Cookie", "theme=dark; Path=/"),
            # bot-manager and load-balancer cookies: random values, but not sessions
            ("Set-Cookie", f"ak_bmsc={RANDOM}; Domain=.example.com; Path=/"),
            ("Set-Cookie", f"bm_sv={RANDOM}; Domain=.example.com; Path=/; Secure"),
            ("Set-Cookie", f"TS0117a65d={RANDOM}; Path=/"),
            ("Set-Cookie", f"AWSALB={RANDOM}; Path=/"),
            ("Set-Cookie", "auth_token=; Max-Age=0; Path=/"),
            ("Set-Cookie", f"zq={RANDOM}; Path=/; Secure; HttpOnly; SameSite=Strict"),
        ], "<p>app</p>")
        # a redirect hop that sets a broad session cookie
        store(pid, "https://app.example.com/login", [
            ("Location", "/"),
            ("Set-Cookie", f"auth={RANDOM}; Domain=.example.com; Path=/; Secure; HttpOnly; "
                           "SameSite=None")], status=302)
        store(pid, "http://plain.example.com/", html + [
            ("Set-Cookie", "PHPSESSID=abc123def456; path=/; SameSite=Lax")], "<p>plain</p>")
        store(pid, "https://admin.example.com/", html + [
            ("Set-Cookie", "sessionid=zzz; Path=/")], "<p>out of scope</p>")
        db.upsert_assets(pid, [
            ("host", "legacy.example.com", {"resolves": False, "cname": ["gone.herokuapp.com"]}),
            ("host", "shop.example.com", {"resolves": True, "cname": ["shops.myshopify.com"]}),
            ("host", "www.example.com", {"resolves": True, "cname": []}),
        ])
        return pid

    def test_run(self):
        pid = self.seed()
        run_id, calls = self.run_cookies(pid)
        self.assertEqual(db.get_run(run_id)["status"], "done",
                         [e["message"] for e in db.list_events(run_id)])
        self.assertEqual(calls, [])
        findings = db.list_findings(pid, "finding")
        got = {(f["type"], f["title"].split("'")[1], f["target"]) for f in findings}

        self.assertEqual(got, {
            ("cookie_no_secure", "sessionid", "https://app.example.com/"),
            ("cookie_no_httponly", "sessionid", "https://app.example.com/"),
            ("cookie_no_samesite", "sessionid", "https://app.example.com/"),
            # plain-HTTP site: no Secure finding, but HttpOnly still matters
            ("cookie_no_httponly", "PHPSESSID", "http://plain.example.com/"),
            # set on the 302 hop
            ("cookie_no_samesite", "auth", "https://app.example.com/login"),
            ("cookie_broad_domain", "auth", "https://app.example.com/login"),
        })
        broad = next(f for f in findings if f["type"] == "cookie_broad_domain")
        self.assertEqual(broad["evidence"]["points_to_third_party"],
                         ["legacy.example.com → gone.herokuapp.com (does not resolve)",
                          "shop.example.com → shops.myshopify.com"])
        self.assertNotIn(RANDOM, str(findings))  # values are masked
        samesite_none = next(f for f in findings
                             if f["type"] == "cookie_no_samesite" and "auth" in f["title"])
        self.assertIn("SameSite=None", samesite_none["title"])

        inventory = {a["value"]: a["data"] for a in db.get_assets(pid, "cookie")}
        self.assertIn("app.example.com _ga", inventory)
        self.assertFalse(inventory["app.example.com _ga"]["session_like"])
        self.assertFalse(inventory["app.example.com ak_bmsc"]["session_like"])
        self.assertEqual(inventory["app.example.com ak_bmsc"]["set_by_infrastructure"],
                         "Akamai Bot Manager")
        self.assertEqual(inventory["app.example.com TS0117a65d"]["set_by_infrastructure"],
                         "F5 BIG-IP")
        self.assertTrue(inventory[f"app.example.com zq"]["session_like"])
        self.assertNotIn("app.example.com auth_token", inventory)  # deletion, not a cookie
        self.assertFalse(any(k.startswith("admin.") for k in inventory))


class ParseTests(unittest.TestCase):
    page = Page("https://a.example.com/", "https://a.example.com/", 200, [], "", b"", "")

    def test_parse(self):
        c = parse_set_cookie("SID=abc; Domain=.Example.com; secure; HTTPONLY; samesite=strict",
                             self.page)
        self.assertEqual((c.name, c.secure, c.httponly, c.samesite, c.domain),
                         ("SID", True, True, "Strict", ".Example.com"))
        self.assertIsNone(parse_set_cookie("novalue", self.page))
        self.assertIsNone(parse_set_cookie(
            "a=b; Expires=Thu, 01 Jan 1970 00:00:00 GMT", self.page))
        self.assertIsNotNone(parse_set_cookie(
            "a=b; Expires=Fri, 01 Jan 2100 00:00:00 GMT", self.page))


class RedirectHopTests(DbTestCase):
    def test_hops_are_stored_with_their_cookies(self):
        def handler(request):
            if request.url.path == "/login":
                return httpx.Response(302, headers={"Location": "/home",
                                                    "Set-Cookie": "sid=abc; Path=/"})
            return httpx.Response(200, headers={"Content-Type": "text/html"}, text="home")

        pid = db.create_program(PROGRAM)
        program = db.get_program(pid)
        guard = ScopeGuard(program["in_scope"], program["out_of_scope"], True)

        async def go():
            client = TargetClient(program, guard, None, transport=httpx.MockTransport(handler))
            shared = RunShared(program, guard, None, client, None, None)
            fetched = await client.get("https://www.example.com/login", "test")
            BotContext(shared, "recon", "test").save_response(fetched)
            await client.close()
            return fetched
        fetched = asyncio.run(go())
        self.assertEqual(fetched.hops[0].header("set-cookie"), "sid=abc; Path=/")
        hop = db.get_response(pid, "https://www.example.com/login")
        self.assertEqual(hop["status"], 302)
        self.assertIn(["set-cookie", "sid=abc; Path=/"], hop["headers"])
        final = db.get_response(pid, "https://www.example.com/home")
        self.assertEqual((final["status"], bytes(final["body"])), (200, b"home"))


if __name__ == "__main__":
    unittest.main()
