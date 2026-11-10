"""Headers department: judges response headers Recon already collected.

Sends no requests at all. Results are grouped per site (origin) where a
problem is site-wide, and per page where it depends on the page."""
from __future__ import annotations

import hashlib
import re

from .base import Bot, BotContext
from .extract import endpoint
from .stored import Page, by_origin, no_pages_message, pages

DEPT = "headers"


def _examples(items: list[Page], n: int = 5) -> list[str]:
    return [p.url for p in items[:n]]


# ---------- CSP parsing ----------

def parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if tokens:
            name = tokens[0].lower()
            if name not in directives:  # first occurrence wins, as in browsers
                directives[name] = tokens[1:]
    return directives


def enforced_policies(page: Page) -> list[dict[str, list[str]]]:
    """Each enforced policy: every Content-Security-Policy header value (a
    comma can join several), plus <meta> policies. Report-Only does not count."""
    policies = []
    for value in page.header_all("content-security-policy"):
        for policy in value.split(","):
            if policy.strip():
                policies.append(parse_csp(policy))
    for meta in page.html["meta_csp"]:
        if meta.strip():
            policies.append(parse_csp(meta))
    return policies


# Hosts that serve arbitrary libraries or user content; allowlisting them in
# script-src usually lets an attacker load a script gadget (e.g. old AngularJS).
RISKY_SCRIPT_HOSTS = re.compile(
    r"^(?:https?://)?(?:\*\.)?(?:cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|"
    r"[a-z0-9.*-]*googleapis\.com|[a-z0-9.*-]*amazonaws\.com|raw\.githubusercontent\.com|"
    r"[a-z0-9.*-]*github\.io|[a-z0-9.*-]*herokuapp\.com|[a-z0-9.*-]*firebaseapp\.com|"
    r"[a-z0-9.*-]*appspot\.com|www\.google\.com|[a-z0-9.*-]*azurewebsites\.net)(?:/.*)?$", re.I)

ISSUE_TEXT = {
    "no_script_limit": "No script-src or default-src: scripts are not restricted at all",
    "unsafe_inline": "'unsafe-inline' allows inline scripts (no nonce or hash to cancel it)",
    "unsafe_eval": "'unsafe-eval' allows eval() and similar",
    "wildcard": "Wildcard or bare scheme (*, https:, http:, data:) in script sources",
    "risky_hosts": "Script sources include hosts that serve arbitrary libraries or user content",
    "object_src": "object-src not restricted (no object-src and default-src is not 'none')",
    "base_uri": "No base-uri: an injected <base> tag could redirect relative script URLs",
}
SERIOUS = {"no_script_limit", "unsafe_inline", "wildcard"}


def csp_issues(policy: dict[str, list[str]]) -> tuple[set[str], list[str]]:
    issues, risky = set(), []
    scripts = policy.get("script-src", policy.get("default-src"))
    if scripts is None:
        issues.add("no_script_limit")
        scripts = []
    lowered = [s.lower() for s in scripts]
    has_nonce_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                         for s in lowered)
    strict_dynamic = "'strict-dynamic'" in lowered
    if "'unsafe-inline'" in lowered and not has_nonce_hash and not strict_dynamic:
        issues.add("unsafe_inline")
    if "'unsafe-eval'" in lowered:
        issues.add("unsafe_eval")
    if not strict_dynamic:
        if any(s in ("*", "https:", "http:", "data:", "blob:") for s in lowered):
            issues.add("wildcard")
        risky = [s for s in scripts if RISKY_SCRIPT_HOSTS.match(s)]
        if risky:
            issues.add("risky_hosts")
    objects = policy.get("object-src")
    default = [s.lower() for s in policy.get("default-src", [])]
    if objects is None and default != ["'none'"]:
        issues.add("object_src")
    if "base-uri" not in policy:
        issues.add("base_uri")
    return issues, risky


def frame_protected(page: Page) -> tuple[bool, str]:
    """(protected, how). Uses only header policies: <meta> CSP cannot set
    frame-ancestors, and X-Frame-Options ALLOW-FROM is ignored by browsers."""
    for value in page.header_all("content-security-policy"):
        for policy in value.split(","):
            ancestors = parse_csp(policy).get("frame-ancestors")
            if ancestors is not None:
                lowered = [s.lower() for s in ancestors]
                if any(s in ("*", "https:", "http:") for s in lowered):
                    return False, f"frame-ancestors allows any site ({' '.join(ancestors)})"
                return True, f"CSP frame-ancestors {' '.join(ancestors) or '(empty)'}"
    xfo = (page.header("x-frame-options") or "").strip().lower()
    if xfo in ("deny", "sameorigin"):
        return True, f"X-Frame-Options {xfo.upper()}"
    if xfo:
        return False, f"X-Frame-Options '{xfo}' is not honoured by browsers"
    return False, "no X-Frame-Options and no CSP frame-ancestors"


# =====================================================================
class SecurityHeadersBot(Bot):
    id, department = "security_headers", DEPT

    CHECKS = [
        # type, header shown, test(page) -> missing?, severity, https only
        ("missing_csp", "Content-Security-Policy",
         lambda p: not enforced_policies(p), "info", False),
        ("missing_hsts", "Strict-Transport-Security",
         lambda p: not p.header("strict-transport-security"), "low", True),
        ("missing_xfo", "X-Frame-Options",
         lambda p: not frame_protected(p)[0], "info", False),
        ("missing_xcto", "X-Content-Type-Options",
         lambda p: (p.header("x-content-type-options") or "").strip().lower() != "nosniff",
         "info", False),
        ("missing_referrer_policy", "Referrer-Policy",
         lambda p: not p.header("referrer-policy") and not p.html["meta_referrer"], "info", False),
        ("missing_permissions_policy", "Permissions-Policy",
         lambda p: not p.header("permissions-policy") and not p.header("feature-policy"),
         "info", False),
    ]

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        html = [p for p in pages(ctx) if p.is_html]
        flagged = 0
        for site, items in by_origin(html).items():
            for type_, header, missing, severity, https_only in self.CHECKS:
                checked = [p for p in items if p.https or not https_only]
                bad = [p for p in checked if missing(p)]
                if not bad:
                    continue
                flagged += 1
                note = ""
                if type_ == "missing_csp" and any(p.header("content-security-policy-report-only")
                                                  for p in bad):
                    note = " A Report-Only policy is present, but it does not block anything."
                if type_ == "missing_hsts" and site.startswith("https://"):
                    note = " Users who type the address or follow an http:// link can be downgraded."
                ctx.finding(
                    type_, key=site, severity=severity,
                    title=f"Missing {header} on {site}", target=site,
                    detail=f"{len(bad)} of {len(checked)} HTML pages seen on this site do not "
                           f"send {header}.{note} Many programs treat missing headers as out "
                           "of scope unless you show impact.",
                    evidence={"pages_without": f"{len(bad)} of {len(checked)}",
                              "examples": _examples(bad),
                              "observed": bad[0].snapshot(header.lower()),
                              "fetched_at": bad[0].fetched_at})
        ctx.log(f"Checked {len(html)} HTML pages on {len(by_origin(html))} sites; "
                f"{flagged} missing-header results")


# =====================================================================
class CspQualityBot(Bot):
    id, department = "csp_quality", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        groups: dict[tuple[str, str], list[Page]] = {}
        details: dict[tuple[str, str], tuple[set[str], list[str], list[str]]] = {}
        for page in pages(ctx):
            if not page.is_html:
                continue
            policies = enforced_policies(page)
            if not policies:
                continue  # the Security headers bot reports missing CSP
            # A script must pass every policy, so only weaknesses all share count.
            results = [csp_issues(p) for p in policies]
            issues = set.intersection(*(r[0] for r in results))
            if not issues & (SERIOUS | {"unsafe_eval", "risky_hosts"}):
                continue
            risky = sorted({h for r in results for h in r[1]})
            raw = page.header_all("content-security-policy") + page.html["meta_csp"]
            digest = hashlib.sha256("\n".join(raw).encode()).hexdigest()[:16]
            key = (page.origin, digest)
            groups.setdefault(key, []).append(page)
            details[key] = (issues, risky, raw)
        for (site, digest), items in groups.items():
            issues, risky, raw = details[(site, digest)]
            order = [i for i in ISSUE_TEXT if i in issues]
            ctx.finding(
                "weak_csp", key=f"{site}|{digest}",
                severity="low" if issues & SERIOUS else "info",
                title=f"Weak Content-Security-Policy on {site}", target=site,
                detail="The policy would not stop an injected script. This is defence in "
                       "depth: it matters as an impact multiplier for an XSS you find, and "
                       "is rarely accepted on its own.",
                evidence={"weaknesses": [ISSUE_TEXT[i] for i in order],
                          "risky_hosts": risky or None, "policy": raw,
                          "pages": f"{len(items)} pages share this policy",
                          "examples": _examples(items)})
        ctx.log(f"{len(groups)} weak policies found")


# =====================================================================
VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                   "x-generator", "x-runtime-version", "x-version", "via")
HAS_VERSION = re.compile(r"(?:[A-Za-z][\w.-]*[/ ]v?\d+(?:\.\d+)+|^v?\d+(?:\.\d+)+$)")


class VersionDisclosureBot(Bot):
    id, department = "version_disclosure", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        seen: dict[tuple[str, str, str], list[Page]] = {}
        for page in pages(ctx):
            for name in VERSION_HEADERS:
                for value in page.header_all(name):
                    value = value.strip()[:200]
                    if HAS_VERSION.search(value):
                        seen.setdefault((page.origin, name, value), []).append(page)
        for (site, name, value), items in seen.items():
            ctx.finding(
                "version_disclosure", key=f"{site}|{name}|{value}", severity="info",
                title=f"{name.title()} reveals '{value}' on {site}", target=site,
                detail="The exact software version helps match known CVEs. On its own this "
                       "is informational; the Outdated library bot (Content department) "
                       "will check versions against known vulnerabilities.",
                evidence={"header": f"{name}: {value}", "responses": len(items),
                          "examples": _examples(items)})
        ctx.log(f"{len(seen)} version strings disclosed")


# =====================================================================
class CorsBot(Bot):
    id, department = "cors", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        cases: dict[tuple[str, str, str], list[Page]] = {}
        for page in pages(ctx):
            allow = (page.header("access-control-allow-origin") or "").strip()
            if not allow:
                continue
            creds = (page.header("access-control-allow-credentials") or "").strip().lower() == "true"
            if allow == "*" and creds:
                case = "wildcard_credentials"
            elif allow.lower() == "null" and creds:
                case = "null_credentials"
            elif allow.lower().startswith("http://") and creds:
                case = "insecure_origin_credentials"
            else:
                continue
            cases.setdefault((page.origin, case, allow), []).append(page)

        text = {
            "wildcard_credentials": (
                "info", "Access-Control-Allow-Origin: * together with credentials",
                "Browsers refuse credentialed requests with '*', so this exact response is "
                "not exploitable. It suggests a careless CORS setup: check by hand (within "
                "program rules) whether the server reflects a real Origin with credentials."),
            "null_credentials": (
                "medium", "Origin 'null' trusted with credentials",
                "Sandboxed iframes and some redirects send Origin: null, so any site may be "
                "able to read these responses with the victim's cookies. Confirm manually "
                "what data the endpoint returns to a logged-in user."),
            "insecure_origin_credentials": (
                "low", "Plain-HTTP origin trusted with credentials",
                "A network attacker who controls that http:// origin could read these "
                "responses with the victim's cookies. Confirm what data is exposed."),
        }
        for (site, case, allow), items in cases.items():
            severity, label, detail = text[case]
            first = items[0]
            ctx.finding(
                "cors_permissive", key=f"{site}|{case}|{allow}", severity=severity,
                title=f"{label} on {site}", target=first.url, detail=detail,
                evidence={"observed": first.snapshot("access-control-allow-origin",
                                                     "access-control-allow-credentials"),
                          "responses": len(items), "examples": _examples(items),
                          "note": "Seen in normal responses; the bot sent no Origin header."})
        ctx.log(f"{len(cases)} permissive CORS configurations")


# =====================================================================
SENSITIVE_PATH = re.compile(r"/(?:account|profile|settings|admin|dashboard|billing|my|user|"
                            r"users|me|checkout|cart|orders?|login|signin|sign-in|logout|"
                            r"password|reset|api|graphql|oauth|token|session)(?:/|$|\.|\?)", re.I)
SESSION_COOKIE = re.compile(r"sess|sid|auth|token|jwt|login|remember|user", re.I)


def sensitivity(page: Page) -> list[str]:
    reasons = []
    cookies = [c.split("=", 1)[0].strip() for c in page.header_all("set-cookie")]
    session = [c for c in cookies if SESSION_COOKIE.search(c)]
    if session:
        reasons.append(f"sets session-like cookie(s): {', '.join(session[:5])}")
    if any(i["type"] == "password" for f in page.html["forms"] for i in f["inputs"]):
        reasons.append("contains a password field")
    if SENSITIVE_PATH.search(page.path):
        reasons.append("path looks account- or API-related")
    if "json" in page.content_type and reasons:
        reasons.append("returns JSON")
    return reasons


class CacheBot(Bot):
    id, department = "cache", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        flagged = 0
        for page in pages(ctx):
            reasons = sensitivity(page)
            if not reasons:
                continue
            control = (page.header("cache-control") or "").lower()
            pragma = (page.header("pragma") or "").lower()
            protected = any(d in control for d in ("no-store", "private", "no-cache")) or \
                "no-cache" in pragma
            public_with_cookie = "public" in control and page.header_all("set-cookie")
            if protected and not public_with_cookie:
                continue
            flagged += 1
            severity = "low" if public_with_cookie else "info"
            ctx.finding(
                "cache_control_missing", key=endpoint(page.url), severity=severity,
                title=("Cache-Control: public on a response that sets cookies"
                       if public_with_cookie else "Sensitive-looking page can be cached"),
                target=page.url,
                detail="A shared cache or proxy could store this response and serve it to "
                       "someone else. The bot saw it as an anonymous visitor; check by hand "
                       "whether the logged-in version carries personal data.",
                evidence={"why_sensitive": reasons,
                          "observed": page.snapshot("cache-control", "pragma", "expires"),
                          "fetched_at": page.fetched_at})
        ctx.log(f"{flagged} sensitive-looking responses without cache protection")


# =====================================================================
class ClickjackingBot(Bot):
    id, department = "clickjacking", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        flagged = 0
        for page in pages(ctx):
            if not page.is_html:
                continue
            forms = page.html["forms"]
            sensitive = SENSITIVE_PATH.search(page.path)
            if not forms and not sensitive:
                continue  # plain pages are covered by the site-wide X-Frame-Options result
            protected, how = frame_protected(page)
            if protected:
                continue
            flagged += 1
            state_changing = any(f["method"] == "post" or
                                 any(i["type"] == "password" for i in f["inputs"]) for f in forms)
            ctx.finding(
                "clickjacking", key=endpoint(page.url),
                severity="low" if state_changing else "info",
                title=f"Page with {'a form' if forms else 'account features'} can be framed",
                target=page.url,
                detail=f"{how[:1].upper()}{how[1:]}. Another site could load this page invisibly in a frame and "
                       "trick a user into clicking. It only matters if a click here does "
                       "something harmful for a logged-in user: verify that before reporting.",
                evidence={"framing": how,
                          "forms": [f"{f['method'].upper()} {f['action']} "
                                    f"({', '.join(i['name'] for i in f['inputs'])})"
                                    for f in forms[:5]] or None,
                          "observed": page.snapshot("x-frame-options", "content-security-policy"),
                          "fetched_at": page.fetched_at})
        ctx.log(f"{flagged} interactive pages without framing protection")


BOTS = {bot.id: bot for bot in (SecurityHeadersBot(), CspQualityBot(), VersionDisclosureBot(),
                                CorsBot(), CacheBot(), ClickjackingBot())}
