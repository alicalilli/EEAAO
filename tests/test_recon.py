"""Recon department against a fake internet: mock HTTP transport + fake DNS.
Checks the safety rules as much as the results."""
import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import dns.resolver
import dns.rrset
import httpx

from eeaao import db
from eeaao.bots import runner
from eeaao.bots.net import OutOfScope, TargetClient
from eeaao.scope import ScopeGuard

SOURCES = {"crt.sh", "api.certspotter.com", "otx.alienvault.com", "web.archive.org",
           "api.github.com"}

HOME = """<!doctype html><html><head><title>Example Home</title>
<meta name="generator" content="WordPress 6.1">
<script src="/static/app.js"></script>
<script src="https://cdn.thirdparty.net/lib.js"></script></head>
<body>
<a href="/about?lang=en">About</a>
<a href="/private/secret">Private</a>
<a href="/logout">Log out</a>
<a href="https://admin.example.com/panel">Admin</a>
<a href="https://twitter.com/examplecorp">Twitter</a>
<a href="/go?next=/home">Go</a>
<form action="/search" method="get"><input name="q"><input type="submit"></form>
<form action="/login" method="post"><input name="user"><input name="password" type="password"></form>
<img src="https://example-assets.s3.amazonaws.com/logo.png">
</body></html>"""

APP_JS = "fetch('/api/v1/users'); const b = 'https://storage.googleapis.com/example-backups/x';"


class FakeInternet:
    def __init__(self):
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        host, path = request.url.host, request.url.path
        if host == "crt.sh":
            return httpx.Response(200, json=[
                {"name_value": "www.example.com\n*.example.com", "common_name": "example.com"},
                {"name_value": "admin.example.com\napi.example.com", "common_name": ""},
                {"name_value": "evil.com", "common_name": ""}])
        if host == "api.certspotter.com":
            return httpx.Response(200, json=[{"id": "1", "dns_names": ["dead.example.com"]}])
        if host == "otx.alienvault.com":
            return httpx.Response(200, json={"passive_dns": [{"hostname": "api.example.com"}]})
        if host == "web.archive.org":
            return httpx.Response(200, json=[
                ["original", "timestamp", "statuscode", "mimetype"],
                ["https://www.example.com/old/dump.sql", "20190101000000", "200", "text/plain"],
                ["https://www.example.com/search?q=x&page=2", "20200101000000", "200", "text/html"],
                ["https://admin.example.com/secret.zip", "20200101000000", "200", "x"]])
        if host == "api.github.com":
            return httpx.Response(500)
        if host == "admin.example.com":
            raise AssertionError("out-of-scope host was contacted")
        if host == "www.example.com":
            routes = {
                "/": (200, "text/html", HOME),
                "/robots.txt": (200, "text/plain",
                                "User-agent: *\nDisallow: /private/\n"
                                "Sitemap: https://www.example.com/sitemap.xml\n"),
                "/sitemap.xml": (200, "application/xml",
                                 "<urlset><url><loc>https://www.example.com/products</loc></url>"
                                 "<url><loc>https://admin.example.com/x</loc></url></urlset>"),
                "/.well-known/security.txt": (200, "text/plain",
                                              "Contact: mailto:security@example.com\n"),
                "/static/app.js": (200, "application/javascript", APP_JS),
                "/about": (200, "text/html", "<a href='/team'>Team</a>"),
                "/products": (200, "text/html", "<p>products</p>"),
                "/team": (200, "text/html", "<p>team</p>"),
                "/search": (200, "text/html", "<p>results</p>"),
            }
            if path == "/go":
                return httpx.Response(302, headers={"Location": "https://evil.com/"})
            status, ctype, body = routes.get(path, (404, "text/html", "<p>nope</p>"))
            return httpx.Response(status, headers={"Content-Type": ctype, "Server": "nginx/1.18.0"},
                                  text=body)
        if host == "api.example.com":
            if request.url.scheme == "http":
                return httpx.Response(301, headers={"Location": "https://api.example.com/"})
            return httpx.Response(200, headers={"Content-Type": "application/json"}, text="{}")
        raise httpx.ConnectError("no route", request=request)


class FakeResolver:
    ZONE = {("www.example.com", "A"): "93.184.216.34",
            ("api.example.com", "A"): "93.184.216.35",
            ("example.com", "A"): "93.184.216.34",
            ("example.com", "MX"): "10 mail.example.com.",
            ("example.com", "TXT"): '"v=spf1 -all"',
            ("example.com", "NS"): "ns1.example.com.",
            ("dead.example.com", "CNAME"): "gone.herokuapp.com."}

    def __init__(self):
        self.asked = []

    async def resolve(self, name, rtype, raise_on_no_answer=True):
        self.asked.append((name, rtype))
        value = self.ZONE.get((name, rtype))
        if value is None:
            if any(n == name for n, _ in self.ZONE):
                return SimpleNamespace(response=SimpleNamespace(answer=[]))
            raise dns.resolver.NXDOMAIN()
        rrset = dns.rrset.from_text(name + ".", 300, "IN", rtype, value)
        return SimpleNamespace(response=SimpleNamespace(answer=[rrset]))


PROGRAM = {"name": "Example", "url": "", "in_scope": "*.example.com\nexample.com",
           "out_of_scope": "admin.example.com", "rate_limit": 1000,
           "headers": {"X-Bug-Bounty": "tester"}, "automation_allowed": True, "notes": "",
           "excluded_types": []}


class DbTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._old = db.DB_PATH
        db.DB_PATH = Path(self._tmp.name) / "test.db"
        db.init()

    def tearDown(self):
        db.DB_PATH = self._old
        self._tmp.cleanup()


class ReconRunTests(DbTestCase):
    def run_recon(self, program_data=PROGRAM, bots=None):
        internet, resolver = FakeInternet(), FakeResolver()
        program_id = db.create_program(program_data)
        program = db.get_program(program_id)

        async def go():
            run_id = runner.start(program, "recon", bots, {}, transport=httpx.MockTransport(internet),
                                  resolver=resolver)
            await runner.wait(run_id)
            return run_id
        run_id = asyncio.run(go())
        return program_id, run_id, internet, resolver

    def values(self, program_id, kind):
        return {a["value"]: a["data"] for a in db.get_assets(program_id, kind)}

    def test_full_recon_run(self):
        program_id, run_id, internet, resolver = self.run_recon()
        run = db.get_run(run_id)
        events = [e["message"] for e in db.list_events(run_id)]
        self.assertEqual(run["status"], "done", events)

        # --- safety ---
        targets = [r for r in internet.calls if r.url.host not in SOURCES]
        self.assertTrue(targets)
        for request in targets:
            self.assertIn(request.method, ("GET", "HEAD"))
            self.assertEqual(request.headers.get("X-Bug-Bounty"), "tester")
            self.assertTrue(request.url.host.endswith("example.com"))
            self.assertNotEqual(request.url.host, "admin.example.com")
            self.assertNotIn("/private/", request.url.path, "robots.txt was not respected")
            self.assertNotIn("/logout", request.url.path)
            self.assertNotEqual(request.url.path, "/login", "a form was submitted")
            self.assertNotEqual(request.url.path, "/old/dump.sql", "archived URL was requested")
            self.assertNotEqual(request.url.host, "evil.com")
        for request in internet.calls:
            if request.url.host in SOURCES:
                self.assertNotIn("X-Bug-Bounty", request.headers)
        self.assertNotIn(("admin.example.com", "A"), resolver.asked)
        total, logged = db.list_requests(program_id, 500, 0)
        http_logged = [r for r in logged if r["kind"] in ("target", "source")]
        self.assertEqual(len(http_logged), len(internet.calls))
        self.assertTrue(any(r["kind"] == "dns" for r in logged))

        # --- results ---
        hosts = self.values(program_id, "host")
        self.assertIn("www.example.com", hosts)
        self.assertIn("api.example.com", hosts)
        self.assertNotIn("admin.example.com", hosts)
        self.assertNotIn("evil.com", hosts)
        self.assertEqual(set(hosts["api.example.com"]["sources"]), {"crt.sh", "otx"})
        self.assertFalse(hosts["dead.example.com"]["resolves"])
        self.assertEqual(hosts["dead.example.com"]["cname"], ["gone.herokuapp.com"])

        dns_records = self.values(program_id, "dns")
        self.assertEqual(dns_records["example.com"]["records"]["TXT"], ["v=spf1 -all"])

        sites = self.values(program_id, "site")
        self.assertEqual(sites["https://www.example.com/"]["title"], "Example Home")
        self.assertIn("nginx 1.18.0", sites["https://www.example.com/"]["tech"])
        self.assertEqual(sites["http://api.example.com/"]["final_url"], "https://api.example.com/")

        files = self.values(program_id, "publicfile")
        self.assertEqual(files["https://www.example.com/robots.txt"]["kind"], "robots.txt")
        self.assertIn("https://www.example.com/.well-known/security.txt", files)

        urls = self.values(program_id, "url")
        self.assertIn("sitemap", urls["https://www.example.com/products"]["sources"])
        self.assertIn("robots", urls["https://www.example.com/private/"]["sources"])
        self.assertIn("https://www.example.com/team", urls)
        self.assertNotIn("https://admin.example.com/x", urls)

        params = self.values(program_id, "param")
        self.assertIn("https://www.example.com/about ? lang", params)
        self.assertIn("https://www.example.com/search ? q", params)
        self.assertIn("https://www.example.com/search ? page", params)
        self.assertIn("https://www.example.com/login ? password", params)

        forms = self.values(program_id, "form")
        self.assertIn("POST https://www.example.com/login", forms)

        js = self.values(program_id, "js")
        self.assertIn("https://www.example.com/static/app.js", js)
        self.assertIsNotNone(db.get_response(program_id, "https://www.example.com/static/app.js"))

        external = self.values(program_id, "external")
        self.assertIn("https://twitter.com/examplecorp", external)
        self.assertIn("https://admin.example.com/panel", external)

        buckets = self.values(program_id, "bucket")
        self.assertIn("Amazon S3: example-assets", buckets)
        self.assertIn("Google Cloud Storage: example-backups", buckets)

        leads = db.list_findings(program_id, "lead")
        types = {(l["type"], l["target"]) for l in leads}
        self.assertIn(("archive_interesting_file", "https://www.example.com/old/dump.sql"), types)
        self.assertFalse(any("admin.example.com" in t for _, t in types))
        self.assertTrue(any(t == "bucket_reference" for t, _ in types))

        # GitHub bot without a token skips politely
        self.assertTrue(any("No GitHub token" in m for m in events))

    def test_rerun_deduplicates(self):
        program_id, *_ = self.run_recon()
        leads_before = db.list_findings(program_id, "lead")
        program = db.get_program(program_id)

        async def again():
            run_id = runner.start(program, "recon", None, {},
                                  transport=httpx.MockTransport(FakeInternet()),
                                  resolver=FakeResolver())
            await runner.wait(run_id)
        asyncio.run(again())
        leads_after = db.list_findings(program_id, "lead")
        self.assertEqual(len(leads_before), len(leads_after))
        self.assertTrue(all(l["hits"] == 2 for l in leads_after))

    def test_automation_off_refuses(self):
        program_id = db.create_program(dict(PROGRAM, automation_allowed=False))

        async def go():
            runner.start(db.get_program(program_id), "recon", None, {})
        with self.assertRaises(runner.RunRefused):
            asyncio.run(go())

    def test_unbuilt_department_refused(self):
        program_id = db.create_program(PROGRAM)

        async def go():
            runner.start(db.get_program(program_id), "no-such-department", None, {})
        with self.assertRaises(runner.RunRefused):
            asyncio.run(go())


class TargetClientTests(DbTestCase):
    def client(self, handler, rate=1000):
        program_id = db.create_program(dict(PROGRAM, rate_limit=rate))
        program = db.get_program(program_id)
        guard = ScopeGuard(program["in_scope"], program["out_of_scope"], True)
        return TargetClient(program, guard, None, transport=httpx.MockTransport(handler))

    def test_refuses_out_of_scope_and_non_get(self):
        async def go():
            client = self.client(lambda r: httpx.Response(200))
            with self.assertRaises(OutOfScope):
                await client.get("https://admin.example.com/", "test")
            with self.assertRaises(OutOfScope):
                await client.get("https://evil.com/", "test")
            with self.assertRaises(ValueError):
                await client.get("https://www.example.com/", "test", method="POST")
            await client.close()
        asyncio.run(go())

    def test_redirect_out_of_scope_not_followed(self):
        seen = []

        def handler(request):
            seen.append(str(request.url))
            if request.url.path == "/a":
                return httpx.Response(302, headers={"Location": "/b"})
            if request.url.path == "/b":
                return httpx.Response(302, headers={"Location": "https://admin.example.com/"})
            return httpx.Response(200)

        async def go():
            client = self.client(handler)
            result = await client.get("https://www.example.com/a", "test")
            await client.close()
            return result
        result = asyncio.run(go())
        self.assertEqual(result.final_url, "https://www.example.com/b")
        self.assertEqual(result.blocked_redirect, "https://admin.example.com/")
        self.assertEqual(seen, ["https://www.example.com/a", "https://www.example.com/b"])

    def test_rate_limit_spacing(self):
        async def go():
            client = self.client(lambda r: httpx.Response(200), rate=20)
            loop = asyncio.get_running_loop()
            start = loop.time()
            await asyncio.gather(*(client.get("https://www.example.com/", "t") for _ in range(6)))
            await client.close()
            return loop.time() - start
        elapsed = asyncio.run(go())
        self.assertGreaterEqual(elapsed, 0.24)  # 6 requests at 20/s: 5 gaps of 50 ms

    def test_body_cap(self):
        async def go():
            client = self.client(lambda r: httpx.Response(200, content=b"x" * 5000))
            result = await client.get("https://www.example.com/", "t", max_body=1000)
            await client.close()
            return result
        result = asyncio.run(go())
        self.assertEqual(len(result.body), 1000)
        self.assertTrue(result.truncated)


class GuardHelperTests(unittest.TestCase):
    def test_host_check_and_seeds(self):
        guard = ScopeGuard("*.example.com\nhttps://shop.example.org/api/\napi-*.example.net\n"
                           "203.0.113.7\n198.51.100.0/24",
                           "admin.example.com\nexample.com/blog", True)
        self.assertTrue(guard.check_host_automated("www.example.com").allowed)
        self.assertTrue(guard.check_host_automated("shop.example.org").allowed)  # path-limited
        self.assertFalse(guard.check_host_automated("admin.example.com").allowed)
        self.assertFalse(guard.check_host_automated("example.com").allowed)
        self.assertFalse(guard.check_host_automated("https://www.example.com/").allowed)
        self.assertEqual(guard.seed_domains(), ["example.com", "example.net"])
        self.assertEqual(guard.seed_hosts(), ["shop.example.org", "203.0.113.7"])
        off = ScopeGuard("*.example.com", "", False)
        self.assertFalse(off.check_host_automated("www.example.com").allowed)


class ExtractTests(unittest.TestCase):
    def test_buckets(self):
        from eeaao.bots.extract import find_buckets
        names = {(p, n) for p, n, _ in find_buckets(
            "https://acme-media.s3.amazonaws.com/logo.png https://s3.eu-west-1.amazonaws.com/other-b/x "
            "s3://third-b gs://g-b https://acct1.blob.core.windows.net/box")}
        self.assertEqual(names, {("Amazon S3", "acme-media"), ("Amazon S3", "other-b"),
                                 ("Amazon S3", "third-b"), ("Google Cloud Storage", "g-b"),
                                 ("Azure Blob Storage", "acct1/box")})

    def test_secrets_skip_placeholders(self):
        from eeaao.bots.extract import find_secrets
        found = find_secrets('key = "AKIAQWERTYUIOPASDFGH"; password = "changeme123"; '
                             'api_key: "YOUR_API_KEY_HERE"')
        self.assertEqual([f["label"] for f in found], ["AWS access key ID"])
        self.assertNotIn("QWERTYUIOPASDFGH", found[0]["masked"])


class ApiTests(DbTestCase):
    def test_exclusions_mark_findings(self):
        from fastapi.testclient import TestClient
        from eeaao.app import app
        client = TestClient(app, base_url="http://127.0.0.1")
        body = dict(PROGRAM, excluded_types=["bucket_reference"])
        created = client.post("/api/programs", json=body)
        self.assertEqual(created.status_code, 201, created.text)
        program_id = created.json()["id"]
        bad = client.post("/api/programs", json=dict(PROGRAM, excluded_types=["nope"]))
        self.assertEqual(bad.status_code, 422)
        for type_ in ("bucket_reference", "archive_interesting_file"):
            db.upsert_finding(program_id, {
                "kind": "lead", "type": type_, "department": "recon", "bot": "x",
                "severity": "info", "title": "t", "target": "https://www.example.com/",
                "detail": "", "evidence": {}, "key": type_})
        leads = client.get(f"/api/programs/{program_id}/findings?kind=lead").json()
        flags = {l["type"]: l["excluded"] for l in leads}
        self.assertEqual(flags, {"bucket_reference": True, "archive_interesting_file": False})
        catalog = client.get("/api/catalog").json()
        recon = next(d for d in catalog if d["id"] == "recon")
        self.assertTrue(recon["runnable"])
        self.assertEqual(len(recon["bots"]), 8)
        settings = client.put("/api/settings/github-token", json={"token": "ghp_" + "a" * 36})
        self.assertTrue(settings.json()["github_token_set"])
        self.assertNotIn("ghp_", json.dumps(client.get("/api/settings").json()))


if __name__ == "__main__":
    unittest.main()
