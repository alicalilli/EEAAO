import unittest

from eeaao.scope import Rule, ScopeError, ScopeGuard, parse_scope_text

IN = """
*.example.com
example.com
https://shop.example.org/api/
api-*.example.net
pay.example.net:8443
203.0.113.0/24
"""
OUT = """
admin.example.com
*.internal.example.com
example.com/blog
203.0.113.9
http://legacy.example.com
"""


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.guard = ScopeGuard(IN, OUT, automation_allowed=True)
        self.assertEqual(self.guard.errors, [])

    def ok(self, target):
        decision = self.guard.check(target)
        self.assertTrue(decision.allowed, f"{target}: {decision.reason}")

    def no(self, target):
        decision = self.guard.check(target)
        self.assertFalse(decision.allowed, f"{target} was allowed by {decision.rule}")
        return decision

    def test_default_deny(self):
        for t in ("evil.com", "example.com.evil.com", "notexample.com",
                  "evilexample.com", "example.org", "198.51.100.1"):
            self.no(t)

    def test_exact_and_wildcard(self):
        for t in ("example.com", "EXAMPLE.com.", "www.example.com",
                  "a.b.c.example.com", "https://www.example.com/x?y=1",
                  "http://example.com:8080/"):
            self.ok(t)

    def test_wildcard_excludes_apex(self):
        guard = ScopeGuard("*.example.com", "")
        self.assertFalse(guard.check("example.com").allowed)
        self.assertTrue(guard.check("a.example.com").allowed)

    def test_out_of_scope_wins(self):
        for t in ("admin.example.com", "https://admin.example.com/login",
                  "x.internal.example.com", "a.b.internal.example.com",
                  "example.com/blog", "https://example.com/blog/post-1",
                  "https://example.com/BLOG/", "203.0.113.9"):
            self.assertEqual(self.no(t).reason, "Explicitly out of scope.")
        self.ok("https://example.com/blogger")
        self.ok("internal.example.com")
        self.ok("203.0.113.10")

    def test_path_tricks(self):
        self.no("https://example.com/x/../blog/")
        self.no("https://example.com/%62log/")
        self.no("https://example.com/%2562log")
        self.no("https://example.com//blog")
        self.ok("https://shop.example.org/api/v1/items")
        self.no("https://shop.example.org/api/../admin")
        self.no("https://shop.example.org/apiv2")
        self.no("https://shop.example.org/")
        self.assertIn("Only part", self.no("shop.example.org").reason)

    def test_scheme_and_port_limits(self):
        self.no("http://shop.example.org/api/")
        self.no("https://shop.example.org:8443/api/")
        self.ok("https://pay.example.net:8443/")
        self.no("https://pay.example.net/")
        partial = self.no("pay.example.net")
        self.assertIn("Only part", partial.reason)
        # out-of-scope http rule blocks http and scheme-less, not https
        self.no("http://legacy.example.com/")
        self.no("legacy.example.com")
        self.ok("https://legacy.example.com/")

    def test_inner_wildcard(self):
        self.ok("api-eu.example.net")
        self.ok("api-.example.net")
        self.no("api.example.net")
        self.no("api-eu.x.example.net")
        self.no("xapi-eu.example.net")

    def test_hostile_targets(self):
        for t in ("https://example.com@evil.com/", "https://evil.com\\@example.com",
                  "https://example.com evil.com", "ftp://example.com",
                  "javascript://example.com/%0aalert(1)", "", "*.example.com",
                  "https://example.com:99999/", "https://evil.com/?u=example.com",
                  "https://evil.com#example.com", "https://evil.com/example.com"):
            self.no(t)

    def test_ip_rules(self):
        self.ok("203.0.113.200")
        self.ok("http://203.0.113.5:8080/x")
        self.no("203.0.114.1")
        self.no("2001:db8::1")

    def test_automation_switch(self):
        manual = ScopeGuard(IN, OUT, automation_allowed=False)
        self.assertTrue(manual.check("example.com").allowed)
        self.assertFalse(manual.check_automated("example.com").allowed)
        self.assertEqual(manual.filter_automated(["example.com"])[0], [])
        allowed, refused = self.guard.filter_automated(
            ["example.com", "evil.com", "admin.example.com"])
        self.assertEqual(allowed, ["example.com"])
        self.assertEqual(len(refused), 2)


class RuleTests(unittest.TestCase):
    def test_too_broad_wildcards_rejected(self):
        for raw in ("*", "*.com", "*.co.uk", "*.*.com", "example.*",
                    "*example.com", "www.*.com", "foo.*.co.uk"):
            with self.assertRaises(ScopeError, msg=raw):
                Rule.parse(raw)
        Rule.parse("*.example.co.uk")

    def test_bad_rules_rejected(self):
        for raw in ("exa mple.com", "ftp://example.com", "user@example.com",
                    "exam!ple.com", "https://"):
            with self.assertRaises(ScopeError, msg=raw):
                Rule.parse(raw)

    def test_unreadable_rule_fails_closed(self):
        guard = ScopeGuard("example.com", "*.com")
        self.assertEqual(len(guard.errors), 1)
        self.assertFalse(guard.check("example.com").allowed)

    def test_parse_scope_text(self):
        text = "- a.com\n• b.com, c.com  # note\n\n# skip\n*.d.com"
        self.assertEqual(parse_scope_text(text), ["a.com", "b.com", "c.com", "*.d.com"])


if __name__ == "__main__":
    unittest.main()
