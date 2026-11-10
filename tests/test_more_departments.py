"""Content and JavaScript, DNS and takeover, and Leads departments."""
import asyncio
import json
import unittest
from types import SimpleNamespace

import dns.resolver
import dns.rrset
import httpx

from eeaao import db
from eeaao.bots import runner
from eeaao.bots.content import detect_libraries
from eeaao.bots.leads import reflection_context
from tests.test_headers import store
from tests.test_recon import PROGRAM, DbTestCase

AWS = "AKIAQWERTYUIOPASDFGH"
GOOGLE = "AIzaSyA1234567890abcdefghijklmnopqrstuv"
APP_JS = f"""/*! jQuery v3.4.1 | (c) JS Foundation */
var cfg = {{aws: "{AWS}", maps: "{GOOGLE}"}};
fetch("/api/v2/orders"); fetch("https://api.example.com/v1/users");
var ci = "https://jenkins.corp.example.com/job/x"; var db = "http://10.0.3.7:8080/x";
var notIp = "1.2.3"; var img = "/static/logo.png";
function t(e){{return e.local?e.locale:e.internal}}  var svc = "https://db01.internal/status";
//# sourceMappingURL=app.js.map"""
OTHER_JS = "console.log(1)\n//# sourceMappingURL=https://admin.example.com/x.js.map"
SOURCEMAP = {"version": 3, "sources": ["webpack:///src/api.ts", "webpack:///src/admin.ts"],
             "sourcesContent": ["export const k = 1", "..."], "mappings": "AAAA"}


def run_dept(pid, department, handler=None, resolver=None):
    calls = []

    def default(request):
        raise AssertionError(f"{department} sent an unexpected request to {request.url}")

    def recorder(request):
        calls.append(request)
        return (handler or default)(request)

    async def go():
        run_id = runner.start(db.get_program(pid), department, None, {},
                              transport=httpx.MockTransport(recorder), resolver=resolver)
        await runner.wait(run_id)
        return run_id
    run_id = asyncio.run(go())
    run = db.get_run(run_id)
    assert run["status"] == "done", [e["message"] for e in db.list_events(run_id)]
    return run_id, calls


class ContentTests(DbTestCase):
    def seed(self):
        pid = db.create_program(PROGRAM)
        js = [("Content-Type", "application/javascript")]
        store(pid, "https://www.example.com/static/app.js", js, APP_JS)
        store(pid, "https://www.example.com/static/other.js", js, OTHER_JS)
        store(pid, "https://www.example.com/", [("Content-Type", "text/html")],
              "<html><!-- TODO: remove admin password before launch --><body>"
              "You're seeing this error because you have <code>DEBUG = True</code> in your "
              "Django settings file.</body></html>")
        store(pid, "https://www.example.com/missing", [("Content-Type", "text/html")],
              "<b>Fatal error</b>: Uncaught Error in /var/www/app/index.php on line <b>12</b>",
              status=404)
        db.upsert_assets(pid, [
            ("js", "https://www.example.com/static/app.js", {"sources": {"crawler": 1}}),
            ("external", "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.5.8/angular.min.js",
             {"kind": "script", "pages": {"https://www.example.com/": 1}}),
        ])
        return pid

    def handler(self, request):
        if request.url.host == "www.example.com" and request.url.path == "/static/app.js.map":
            return httpx.Response(200, json=SOURCEMAP)
        if request.url.host == "api.osv.dev":
            package = json.loads(request.content)["package"]["name"]
            vulns = {"jquery": [{"id": "GHSA-gxr4-xjj5-5px2", "aliases": ["CVE-2020-11022"],
                                 "summary": "XSS in htmlPrefilter",
                                 "database_specific": {"severity": "MODERATE"}}],
                     "angular": [{"id": "GHSA-5cp4-xmrw-59wf", "aliases": ["CVE-2019-10768"],
                                  "summary": "Prototype pollution",
                                  "database_specific": {"severity": "HIGH"}}]}
            return httpx.Response(200, json={"vulns": vulns.get(package, [])} if package in vulns else {})
        raise AssertionError(f"unexpected request {request.url}")

    def test_run(self):
        pid = self.seed()
        run_id, calls = run_dept(pid, "content", self.handler)
        targets = [str(c.url) for c in calls if c.url.host != "api.osv.dev"]
        self.assertEqual(targets, ["https://www.example.com/static/app.js.map"])
        self.assertEqual(sorted(json.loads(c.content)["package"]["name"]
                                for c in calls if c.url.host == "api.osv.dev"),
                         ["angular", "jquery"])

        findings = db.list_findings(pid, "finding")
        by_type = {}
        for f in findings:
            by_type.setdefault(f["type"], []).append(f)
        secrets = {f["evidence"]["match"]: f["severity"] for f in by_type["js_secret"]}
        self.assertEqual(len(secrets), 2)
        self.assertIn("high", secrets.values())
        self.assertIn("info", secrets.values())  # the Google key
        self.assertNotIn(AWS, json.dumps(findings))

        # "e.local" / "e.internal" in code are properties, not hosts
        self.assertEqual(sorted(f["evidence"]["host"] for f in by_type["internal_host_disclosure"]),
                         ["db01.internal", "jenkins.corp.example.com"])
        self.assertEqual([f["evidence"]["ip"] for f in by_type["internal_ip_disclosure"]],
                         ["10.0.3.7"])
        smap = by_type["sourcemap_exposed"][0]
        self.assertEqual((smap["severity"], smap["evidence"]["files_in_map"]), ("low", 2))

        debug = {f["title"] for f in by_type["debug_info"]}
        self.assertEqual(debug, {"Django debug page in response", "PHP error message in response",
                                 "Server file path in response",
                                 "HTML comments mention sensitive-sounding words"})

        libs = {f["evidence"]["library"]: f["severity"] for f in by_type["outdated_library"]}
        self.assertEqual(libs, {"jquery 3.4.1": "info", "angular 1.5.8": "low"})

        endpoints = {a["value"] for a in db.get_assets(pid, "endpoint")}
        self.assertIn("https://www.example.com/api/v2/orders", endpoints)
        self.assertIn("https://api.example.com/v1/users", endpoints)
        self.assertNotIn("https://www.example.com/static/logo.png", endpoints)
        self.assertIn("jenkins.corp.example.com", {a["value"] for a in db.get_assets(pid, "host")})

    def test_library_detection(self):
        found = detect_libraries([
            "https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js",
            "https://ajax.googleapis.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js",
            "https://www.example.com/js/bootstrap-3.3.7.min.js"], [])
        self.assertEqual(set(found), {("lodash", "4.17.15"), ("jquery-ui", "1.12.1"),
                                      ("bootstrap", "3.3.7")})


class FakeDns:
    ZONE = {("broken.example.com", "NS"): ["ns-1.awsdns-01.org."],
            ("_dmarc.example.com", "TXT"): ['"v=DMARC1; p=none; rua=mailto:d@example.com"'],
            ("mail.example.com", "TXT"): ['"v=spf1 include:_spf.example.net -all"']}

    def __init__(self):
        self.asked = []

    async def resolve(self, name, rtype, raise_on_no_answer=True):
        self.asked.append((name, rtype))
        values = self.ZONE.get((name, rtype))
        if not values:
            raise dns.resolver.NXDOMAIN()
        rrset = dns.rrset.from_text_list(name + ".", 300, "IN", rtype, values)
        return SimpleNamespace(response=SimpleNamespace(answer=[rrset]))


class DnsDepartmentTests(DbTestCase):
    def seed(self):
        pid = db.create_program(PROGRAM)
        db.upsert_assets(pid, [
            ("host", "blog.example.com", {"resolves": True, "cname": ["examplecorp.github.io"]}),
            ("host", "app.example.com", {"resolves": False, "cname": ["exampleapp.azurewebsites.net"]}),
            ("host", "old.example.com", {"resolves": False, "cname": ["x.unknownsvc.net"]}),
            ("host", "cdn.example.com", {"resolves": False, "cname": ["d3nogw076chdmr.cloudfront.net"]}),
            ("dns", "www.example.com", {"status": "NOERROR", "records": {"A": ["93.184.216.34"]}}),
            ("host", "ok.example.com", {"resolves": True, "cname": ["examplecorp.github.io"]}),
            ("host", "internal.example.com", {"resolves": False, "cname": ["lb.example.com"]}),
            ("host", "admin.example.com", {"resolves": False, "cname": ["gone.herokuapp.com"]}),
            ("dns", "broken.example.com", {"status": "SERVFAIL", "records": {"A": []}}),
            ("dns", "example.com", {"status": "NOERROR",
                                    "records": {"A": ["93.184.216.34"], "TXT": ["v=spf1 +all"],
                                                "MX": ["10 mail.example.com"]}}),
            ("dns", "mail.example.com", {"status": "NOERROR", "records": {"MX": ["10 mx.example.net"]}}),
        ])
        store(pid, "https://blog.example.com/", [("Content-Type", "text/html")],
              "<h1>404</h1><p>There isn't a GitHub Pages site here.</p>", status=404)
        store(pid, "https://ok.example.com/", [("Content-Type", "text/html")], "<p>Our blog</p>")
        return pid

    def test_run(self):
        pid = self.seed()
        resolver = FakeDns()
        run_dept(pid, "dns", resolver=resolver)
        self.assertEqual(sorted(resolver.asked), sorted([
            ("broken.example.com", "NS"), ("_dmarc.example.com", "TXT"),
            ("mail.example.com", "TXT"), ("_dmarc.mail.example.com", "TXT")]))
        findings = db.list_findings(pid, "finding")
        takeover = {f["target"]: f["severity"] for f in findings if f["type"] == "subdomain_takeover"}
        self.assertEqual(takeover, {"blog.example.com": "medium", "app.example.com": "medium",
                                    "old.example.com": "low", "cdn.example.com": "info"})
        stale = next(f for f in findings if f["target"] == "cdn.example.com")
        self.assertIn("not claimable", stale["title"])
        self.assertIn("CloudFront", stale["title"])
        ns = next(f for f in findings if f["type"] == "dangling_ns")
        self.assertEqual(ns["evidence"]["known_provider"], ["ns-1.awsdns-01.org"])
        mail = {(f["type"], f["target"], f["severity"]) for f in findings
                if f["type"].startswith(("spf", "dmarc"))}
        self.assertEqual(mail, {("spf_weak", "example.com", "low"),
                                ("dmarc_weak", "example.com", "info"),
                                ("dmarc_missing", "mail.example.com", "info")})
        self.assertFalse(any("admin.example.com" in f["target"] for f in findings))


class LeadsTests(DbTestCase):
    def test_run(self):
        pid = db.create_program(PROGRAM)
        www = "https://www.example.com"
        search_pages = [f"{www}/", f"{www}/shop", f"{www}/shop/tees"]
        db.upsert_assets(pid, [
            ("param", f"{www}/login ? next",
             {"sources": {"crawler": 1}, "example": f"{www}/login?next=https%3A%2F%2Fx.test%2F"}),
            ("param", f"{www}/account ? return_to", {"sources": {"wayback": 1}}),
            ("param", f"{www}/old/account ? return_to", {"sources": {"wayback": 1}}),
            ("param", f"{www}/list ? page", {"sources": {"crawler": 1}}),
            ("param", f"{www}/search ? q", {"sources": {"crawler": 1}}),
            ("param", f"{www}/feedback ? message", {"sources": {"wayback": 1}}),
            ("param", f"{www}/contact ? message", {"sources": {"wayback": 1}}),
            # static files and image resizers: parameters pick a file or a size
            ("param", f"{www}/js/jquery.base.js ? path",
             {"sources": {"wayback": 1}, "example": f"{www}/js/jquery.base.js?path=/2009/2.4"}),
            ("param", f"{www}/img/hero.jpg ? q",
             {"sources": {"crawler": 1}, "example": f"{www}/img/hero.jpg?w=3840&q=75"}),
            ("param", f"{www}/_next/image ? q",
             {"sources": {"crawler": 1}, "example": f"{www}/_next/image?url=%2Fa.jpg&w=64&q=75"}),
            ("param", f"{www}/_next/image ? url",
             {"sources": {"crawler": 1}, "example": f"{www}/_next/image?url=%2Fa.jpg&w=64&q=75"}),
            # an ordinary name whose value is a full URL
            ("param", f"{www}/share ? img",
             {"sources": {"crawler": 1}, "example": f"{www}/share?img=https://cdn.x.test/a.png"}),
            ("param", "https://admin.example.com/a ? url", {"sources": {"crawler": 1}}),
            ("form", f"POST {www}/login", {"inputs": {"user": "input", "password": "password"}}),
        ] + [("form", f"GET {page}", {"inputs": {"search": "text"}, "found_on": page})
             for page in search_pages]
          + [("param", f"{page} ? search", {"sources": {"form": 1}}) for page in search_pages])
        store(pid, f"{www}/search?q=shoes123", [("Content-Type", "text/html")],
              '<form><input name="q" value="shoes123"></form><p>No results</p>')
        run_dept(pid, "leads")
        leads = db.list_findings(pid, "lead")
        redirect = {(l["evidence"]["parameter"], l["severity"]) for l in leads
                    if l["type"] == "lead_redirect_param"}
        self.assertEqual(redirect, {("next", "low"), ("return_to", "info"), ("url", "low"),
                                    ("img", "low")})
        grouped = next(l for l in leads if l["evidence"].get("parameter") == "return_to")
        self.assertEqual(grouped["evidence"]["seen_on"], "2 endpoints")
        resizer = next(l for l in leads if l["evidence"].get("parameter") == "url")
        self.assertIn("Image resizer", resizer["title"])

        xss = {l["title"]: l for l in leads if l["type"] == "lead_xss_param"}
        self.assertEqual(set(xss), {
            "Parameter 'q' is reflected inside an HTML tag",
            "GET form with free-text field search on www.example.com",
            "POST form with free-text field user on www.example.com",
            "Parameter 'message' on www.example.com is the kind often echoed back",
        })
        # the same search box on three pages is one lead
        form = xss["GET form with free-text field search on www.example.com"]
        self.assertEqual(form["evidence"]["seen_on"], "3 pages")
        self.assertEqual(xss["Parameter 'message' on www.example.com is the kind often echoed back"]
                         ["evidence"]["seen_on"], "2 endpoints")
        self.assertFalse(any("admin.example.com" in l["target"] for l in leads))

    def test_reflection_context(self):
        page = "<script>var a = 'XX';</script><p>XX</p><a title='XX'>"
        self.assertEqual(reflection_context(page, page.index("XX")), "inside a <script> block")
        second = page.index("XX", page.index("</script>"))
        self.assertEqual(reflection_context(page, second), "in HTML text")
        self.assertEqual(reflection_context(page, page.rindex("XX")),
                         "inside an HTML tag (attribute)")


if __name__ == "__main__":
    unittest.main()
