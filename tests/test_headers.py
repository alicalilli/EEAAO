"""Headers department: works only from stored responses, never the network."""
import asyncio
import unittest

import httpx

from eeaao import db
from eeaao.bots import runner
from eeaao.bots.headers import csp_issues, parse_csp
from tests.test_recon import PROGRAM, DbTestCase

LOGIN = """<html><head><title>Login</title></head><body>
<form action="/login" method="post"><input name="user"><input name="pw" type="password"></form>
</body></html>"""
GOOD_HEADERS = [
    ("Content-Type", "text/html"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-abc'; "
                                "object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
    ("Strict-Transport-Security", "max-age=31536000"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=()"),
    ("Cache-Control", "no-store"),
]


def store(program_id, url, headers, body="", status=200):
    ctype = next((v for k, v in headers if k.lower() == "content-type"), "")
    db.save_response(program_id, "test", url, url, status, headers, ctype, body.encode(), False)


class HeadersRunTests(DbTestCase):
    def run_headers(self, program_id):
        calls = []

        def offline(request):
            calls.append(request)
            raise AssertionError("the Headers department must not send requests")

        class NoDns:
            async def resolve(self, *a, **k):
                raise AssertionError("no DNS either")

        async def go():
            run_id = runner.start(db.get_program(program_id), "headers", None, {},
                                  transport=httpx.MockTransport(offline), resolver=NoDns())
            await runner.wait(run_id)
            return run_id
        run_id = asyncio.run(go())
        return run_id, calls

    def seed(self):
        pid = db.create_program(PROGRAM)
        # weak site: no security headers, versions, login form, session cookie
        store(pid, "https://www.example.com/login", [
            ("Content-Type", "text/html; charset=utf-8"), ("Server", "nginx/1.18.0"),
            ("X-Powered-By", "PHP/7.4.3"), ("Set-Cookie", "PHPSESSID=abc; path=/")], LOGIN)
        store(pid, "https://www.example.com/", [("Content-Type", "text/html"),
                                                ("Server", "nginx/1.18.0")], "<p>home</p>")
        # good site: nothing to report even with a form on it
        store(pid, "https://good.example.com/account", GOOD_HEADERS, LOGIN)
        # weak CSP + ALLOW-FROM (ignored by browsers)
        store(pid, "https://weak.example.com/", [
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", "script-src 'self' 'unsafe-inline' "
                                        "https://cdnjs.cloudflare.com; object-src 'none'; base-uri 'none'"),
            ("X-Frame-Options", "ALLOW-FROM https://partner.example.org")], "<p>x</p>")
        # CORS cases
        store(pid, "https://api.example.com/api/me", [
            ("Content-Type", "application/json"), ("Access-Control-Allow-Origin", "null"),
            ("Access-Control-Allow-Credentials", "true")], "{}")
        store(pid, "https://api.example.com/api/public", [
            ("Content-Type", "application/json"), ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true")], "{}")
        # must be ignored: out of scope, and an error page
        store(pid, "https://admin.example.com/", [("Content-Type", "text/html"),
                                                  ("Server", "Apache/2.2.1")], LOGIN)
        store(pid, "https://www.example.com/missing", [("Content-Type", "text/html"),
                                                       ("Server", "Apache/9.9")], "", status=404)
        return pid

    def test_run(self):
        pid = self.seed()
        run_id, calls = self.run_headers(pid)
        self.assertEqual(db.get_run(run_id)["status"], "done",
                         [e["message"] for e in db.list_events(run_id)])
        self.assertEqual(calls, [])
        self.assertEqual(db.list_requests(pid, 10, 0)[0], 0)

        findings = db.list_findings(pid, "finding")
        got = {(f["type"], f["target"]) for f in findings}
        www = "https://www.example.com"
        for type_ in ("missing_csp", "missing_hsts", "missing_xfo", "missing_xcto",
                      "missing_referrer_policy", "missing_permissions_policy"):
            self.assertIn((type_, www), got)
        # one card per site, not per page
        self.assertEqual(sum(1 for t, s in got if t == "missing_csp" and s == www), 1)
        self.assertFalse(any("good.example.com" in s for _, s in got), got)
        self.assertFalse(any("admin.example.com" in s for _, s in got), got)
        self.assertFalse(any("Apache" in f["title"] for f in findings))

        versions = {f["title"] for f in findings if f["type"] == "version_disclosure"}
        self.assertEqual(versions, {"Server reveals 'nginx/1.18.0' on https://www.example.com",
                                    "X-Powered-By reveals 'PHP/7.4.3' on https://www.example.com"})

        click = [f for f in findings if f["type"] == "clickjacking"]
        self.assertEqual([(f["target"], f["severity"]) for f in click],
                         [("https://www.example.com/login", "low")])

        weak = next(f for f in findings if f["type"] == "weak_csp")
        self.assertEqual(weak["severity"], "low")
        self.assertTrue(any("unsafe-inline" in w for w in weak["evidence"]["weaknesses"]))
        self.assertEqual(weak["evidence"]["risky_hosts"], ["https://cdnjs.cloudflare.com"])
        self.assertIn(("missing_xfo", "https://weak.example.com"), got)

        cors = {f["evidence"]["observed"]["access-control-allow-origin"]: f["severity"]
                for f in findings if f["type"] == "cors_permissive"}
        self.assertEqual(cors, {"null": "medium", "*": "info"})

        cache = [f for f in findings if f["type"] == "cache_control_missing"]
        self.assertEqual({f["target"] for f in cache},
                         {"https://www.example.com/login", "https://api.example.com/api/me",
                          "https://api.example.com/api/public"})  # good.example.com has no-store

        # running again only bumps the counters
        self.run_headers(pid)
        again = db.list_findings(pid, "finding")
        self.assertEqual(len(again), len(findings))
        self.assertTrue(all(f["hits"] == 2 for f in again))

    def test_no_stored_responses(self):
        pid = db.create_program(PROGRAM)
        run_id, calls = self.run_headers(pid)
        self.assertEqual(calls, [])
        self.assertTrue(any("Run the Recon department first" in e["message"]
                            for e in db.list_events(run_id)))


class CspTests(unittest.TestCase):
    def issues(self, policy):
        return csp_issues(parse_csp(policy))[0]

    def test_nonce_cancels_unsafe_inline(self):
        self.assertNotIn("unsafe_inline", self.issues("script-src 'self' 'unsafe-inline' 'nonce-x'"))
        self.assertIn("unsafe_inline", self.issues("script-src 'self' 'unsafe-inline'"))

    def test_default_src_fallback_and_missing(self):
        self.assertIn("wildcard", self.issues("default-src *"))
        self.assertIn("no_script_limit", self.issues("img-src 'self'"))
        self.assertNotIn("object_src", self.issues("default-src 'none'; script-src 'self'"))

    def test_strict_dynamic_ignores_allowlist(self):
        found = self.issues("script-src 'nonce-a' 'strict-dynamic' https: 'unsafe-inline'")
        self.assertFalse(found & {"wildcard", "unsafe_inline", "risky_hosts"})


if __name__ == "__main__":
    unittest.main()
