"""Cookies department: judges Set-Cookie headers Recon already stored
(including those set on redirect responses). Sends no requests.

Only cookies that look like they carry a session or identity are flagged:
analytics, consent and preference cookies missing a flag are normal and would
bury the useful results. Every cookie, flagged or not, goes into the
inventory with its attributes so you can browse them."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

from .. import db
from .base import Bot, BotContext
from .extract import mask
from .stored import Page, no_pages_message, responses

DEPT = "cookies"

SESSION_NAME = re.compile(
    r"sess|^sid$|[_.-]sid$|^sid[_.-]|auth|token|jwt|login|remember|^user|_user$|account|"
    r"identity|^id$|^jsessionid$|^phpsessid$|asp\.net_sessionid|connect\.sid|_session$", re.I)
CSRF_NAME = re.compile(r"csrf|xsrf", re.I)
NOT_SESSION = re.compile(
    r"^(?:_ga|_gid|_gat|_gcl|_fbp|_fbc|__utm|_hj|ajs_|mp_|amplitude|optimizely|_uet|_clck|_clsk|"
    r"OptanonConsent|OptanonAlertBoxClosed|CookieConsent|cookielawinfo|euconsent|"
    r"lang|locale|language|theme|timezone|currency|country|__cf_bm|_cfuvid|cf_clearance)",
    re.I)
# Cookies set by CDNs, WAFs, bot managers and load balancers. Their values look
# random, but they do not carry a user's login, so their flags are not findings.
INFRASTRUCTURE = [
    ("Akamai Bot Manager", re.compile(r"^(?:ak_bmsc|bm_sv|bm_sz|bm_mi|bm_so|bm_s|bm_ss|_abck|akavpau_|akaalb_|AKA_A2$|RT$)", re.I)),
    ("F5 BIG-IP", re.compile(r"^(?:TS[0-9a-f]{6,}|BIGipServer|F5_|MRHSession$|LastMRH_Session$)", re.I)),
    ("Cloudflare", re.compile(r"^(?:__cf_bm|_cfuvid|cf_clearance|__cflb|__cfruid|cf_ob_info|cf_use_ob|CF_AppSession)", re.I)),
    ("Imperva / Incapsula", re.compile(r"^(?:incap_ses_|visid_incap_|nlbi_|reese84$|___utmvc)", re.I)),
    ("AWS load balancer / WAF", re.compile(r"^(?:AWSALB|AWSALBCORS|AWSALBTG|AWSELB|aws-waf-token)", re.I)),
    ("Azure load balancer", re.compile(r"^(?:ARRAffinity|ARRAffinitySameSite|ApplicationGatewayAffinity)", re.I)),
    ("DataDome", re.compile(r"^datadome$", re.I)),
    ("PerimeterX / HUMAN", re.compile(r"^_px(?:hd|vid|3|2|de)?$|^pxcts$", re.I)),
    ("Google Cloud load balancer", re.compile(r"^GCLB$", re.I)),
    ("Sucuri", re.compile(r"^sucuri_cloudproxy", re.I)),
    ("HAProxy / generic balancer", re.compile(r"^(?:SERVERID|SRVNAME|ROUTEID|lb_?cookie|sticky)", re.I)),
]


def infrastructure(name: str) -> str | None:
    return next((label for label, pattern in INFRASTRUCTURE if pattern.match(name)), None)


@dataclass
class Cookie:
    name: str
    value: str
    secure: bool
    httponly: bool
    samesite: str | None
    domain: str | None
    path: str | None
    page: Page

    @property
    def host(self) -> str:
        return (urlsplit(self.page.url).hostname or "").lower()

    @property
    def masked(self) -> str:
        """The Set-Cookie line with the value masked."""
        parts = [f"{self.name}={mask(self.value) if len(self.value) > 4 else '…'}"]
        if self.domain:
            parts.append(f"Domain={self.domain}")
        if self.path:
            parts.append(f"Path={self.path}")
        if self.secure:
            parts.append("Secure")
        if self.httponly:
            parts.append("HttpOnly")
        if self.samesite:
            parts.append(f"SameSite={self.samesite}")
        return "; ".join(parts)

    @property
    def csrf(self) -> bool:
        return bool(CSRF_NAME.search(self.name))

    def session_reason(self) -> str | None:
        if NOT_SESSION.search(self.name) or infrastructure(self.name):
            return None
        if self.csrf:
            return None  # an anti-CSRF token is not a login; its flags are not session issues
        if SESSION_NAME.search(self.name):
            return "name looks like a session/auth cookie"
        if _looks_random(self.value):
            return "value looks like a random token"
        return None


def _looks_random(value: str) -> bool:
    value = value.strip('"')
    if len(value) < 20:
        return False
    counts = Counter(value)
    entropy = -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())
    return entropy >= 3.5


def _deleted(value: str, attrs: dict[str, str]) -> bool:
    if value in ("", '""', "deleted"):
        return True
    max_age = attrs.get("max-age")
    if max_age is not None:
        try:
            return int(max_age) <= 0
        except ValueError:
            pass
    expires = attrs.get("expires")
    if expires:
        try:
            when = parsedate_to_datetime(expires)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return when < datetime.now(timezone.utc)
        except (TypeError, ValueError, IndexError, OverflowError):
            pass
    return False


def parse_set_cookie(line: str, page: Page) -> Cookie | None:
    parts = line.split(";")
    name, sep, value = parts[0].partition("=")
    name, value = name.strip(), value.strip()
    if not sep or not name:
        return None
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.partition("=")
        key = key.strip().lower()
        if key and key not in attrs:
            attrs[key] = val.strip()
    if _deleted(value, attrs):
        return None
    samesite = attrs.get("samesite")
    return Cookie(name=name, value=value, secure="secure" in attrs, httponly="httponly" in attrs,
                  samesite=samesite.capitalize() if samesite else None,
                  domain=attrs.get("domain") or None, path=attrs.get("path") or None, page=page)


def all_cookies(ctx: BotContext) -> list[Cookie]:
    cache = ctx.shared.cache
    if "cookies" not in cache:
        found = []
        for page in responses(ctx):
            for line in page.header_all("set-cookie"):
                cookie = parse_set_cookie(line, page)
                if cookie:
                    found.append(cookie)
        cache["cookies"] = found
    return cache["cookies"]


def grouped(cookies: list[Cookie]) -> dict[tuple[str, str], list[Cookie]]:
    groups: dict[tuple[str, str], list[Cookie]] = {}
    for cookie in cookies:
        groups.setdefault((cookie.host, cookie.name), []).append(cookie)
    return groups


def _evidence(cookie: Cookie, instances: list[Cookie], reason: str) -> dict:
    urls = list(dict.fromkeys(c.page.requested for c in instances))
    return {"set_cookie": cookie.masked, "why_session_like": reason,
            "set_by": urls[:5], "responses": len(instances),
            "response_status": cookie.page.status, "fetched_at": cookie.page.fetched_at}


# =====================================================================
class CookieFlagsBot(Bot):
    id, department = "cookie_flags", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        groups = grouped(all_cookies(ctx))
        if not groups:
            ctx.log("No cookies were set in the stored responses.")
            return
        flagged = sessions = 0
        for (host, name), instances in groups.items():
            first = instances[0]
            reason = first.session_reason()
            ctx.asset("cookie", f"{host} {name}", {
                "set_cookie": first.masked, "session_like": bool(reason),
                "set_by_infrastructure": infrastructure(name),
                "set_by": {c.page.requested: 1 for c in instances[:5]}})
            if not reason:
                continue
            sessions += 1
            label = f"'{name}' on {host}"

            over_https = [c for c in instances if c.page.https and not c.secure
                          and not name.startswith(("__Secure-", "__Host-"))]
            if over_https:
                flagged += 1
                ctx.finding(
                    "cookie_no_secure", key=f"{host}|{name}", severity="low",
                    title=f"Session-like cookie {label} without Secure",
                    target=over_https[0].page.url,
                    detail="The cookie is set over HTTPS but may also be sent over plain "
                           "HTTP, where a network attacker can read it. Check whether the "
                           "host still answers on http:// and whether HSTS covers it.",
                    evidence=_evidence(over_https[0], instances, reason))

            no_httponly = [c for c in instances if not c.httponly]
            if no_httponly and not first.csrf:
                flagged += 1
                ctx.finding(
                    "cookie_no_httponly", key=f"{host}|{name}", severity="low",
                    title=f"Session-like cookie {label} without HttpOnly",
                    target=no_httponly[0].page.url,
                    detail="JavaScript on the page can read this cookie, so any XSS could "
                           "steal it. Confirm it really is a session cookie (log in and see "
                           "whether it changes) before reporting; on its own this is rarely "
                           "accepted, but it raises the impact of an XSS.",
                    evidence=_evidence(no_httponly[0], instances, reason))

            weak_samesite = [c for c in instances if c.samesite in (None, "None")]
            if weak_samesite:
                flagged += 1
                cookie = weak_samesite[0]
                missing = cookie.samesite is None
                ctx.finding(
                    "cookie_no_samesite", key=f"{host}|{name}", severity="info",
                    title=(f"Session-like cookie {label} without SameSite" if missing
                           else f"Session-like cookie {label} with SameSite=None"),
                    target=cookie.page.url,
                    detail=("Chrome and Edge treat a missing SameSite as Lax, but Safari and "
                            "Firefox do not, so the cookie may be sent with cross-site "
                            "requests. " if missing else
                            "The cookie is sent with every cross-site request. ") +
                           "This is a pointer for CSRF testing, not a finding by itself."
                           + ("" if cookie.secure or missing else
                              " SameSite=None without Secure is rejected by browsers."),
                    evidence=_evidence(cookie, instances, reason))
        ctx.flush()
        ctx.log(f"{len(groups)} cookies seen, {sessions} session-like, {flagged} flag problems")


# =====================================================================
class CookieScopeBot(Bot):
    id, department = "cookie_scope", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        hosts = db.get_assets(ctx.program_id, "host")
        flagged = 0
        for (host, name), instances in grouped(all_cookies(ctx)).items():
            broad = []
            for cookie in instances:
                domain = (cookie.domain or "").lstrip(".").lower()
                if domain and domain != host and host.endswith("." + domain):
                    broad.append((cookie, domain))
            if not broad:
                continue
            cookie, domain = broad[0]
            reason = cookie.session_reason()
            if not reason:
                continue  # analytics cookies on the parent domain are normal
            flagged += 1
            under = [a for a in hosts if a["value"] == domain or a["value"].endswith("." + domain)]
            dangling = []
            for asset in under:
                cname = asset["data"].get("cname") or []
                if cname and (asset["data"].get("resolves") is False or
                              not any(c == domain or c.endswith("." + domain) for c in cname)):
                    dangling.append(f"{asset['value']} → {cname[-1]}"
                                    + (" (does not resolve)" if asset["data"].get("resolves") is False
                                       else ""))
            ctx.finding(
                "cookie_broad_domain", key=f"{domain}|{name}", severity="low",
                title=f"Session-like cookie '{name}' shared with every *.{domain} host",
                target=cookie.page.url,
                detail=f"{host} sets Domain={cookie.domain}, so browsers send this cookie to "
                       f"all subdomains of {domain}. Anyone who controls one of them (a "
                       "taken-over subdomain, a third-party hosted page, a user-content "
                       "host) receives it. The Takeover bot will check subdomains that "
                       "point to third-party services; treat the list below as leads.",
                evidence={**_evidence(cookie, [c for c, _ in broad], reason),
                          "known_hosts_under_domain": len(under),
                          "points_to_third_party": dangling[:10] or None})
        ctx.log(f"{flagged} session-like cookies scoped to a parent domain")


BOTS = {bot.id: bot for bot in (CookieFlagsBot(), CookieScopeBot())}
