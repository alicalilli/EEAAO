"""Third-party links department.

Never visits a linked third-party site: those are out of scope. Instead:
  Broken link bot   - asks the domain's registry (RDAP, the official successor
                      of WHOIS) whether the linked domain is still registered.
                      The registry servers come from IANA's bootstrap list.
  Social handle bot - checks handles through public platform APIs (GitHub,
                      GitLab). Links to other platforms are listed for manual
                      checking; nothing is requested from those platforms.
"""
from __future__ import annotations

import ipaddress
import os
import re
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

from .. import db
from ..scope import _BROAD_SUFFIXES
from .base import Bot, BotContext

DEPT = "thirdparty"

# Domains that are certainly registered; asking a registry about them wastes
# its time and ours.
WELL_KNOWN = {
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com", "google-analytics.com",
    "youtube.com", "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "tiktok.com", "pinterest.com", "reddit.com", "github.com", "gitlab.com",
    "github.io", "apple.com", "microsoft.com", "live.com", "amazon.com", "amazonaws.com",
    "cloudflare.com", "cloudfront.net", "jsdelivr.net", "jquery.com", "unpkg.com",
    "cdnjs.com", "bootstrapcdn.com", "w3.org", "schema.org", "wikipedia.org", "mozilla.org",
    "medium.com", "t.me", "telegram.org", "discord.gg", "discord.com", "whatsapp.com",
    "wordpress.org", "wordpress.com", "gravatar.com", "fonts.net", "typekit.net",
    "hotjar.com", "doubleclick.net", "stripe.com", "paypal.com", "zendesk.com", "hubspot.com",
}
TAG_WEIGHT = {"script": 3, "iframe": 2, "frame": 2, "embed": 2, "object": 2, "link": 2,
              "form": 2, "a": 1, "area": 1, "meta": 1, "img": 1, "source": 1}
SEVERITY = {3: "high", 2: "medium", 1: "low"}
LOWER = {"high": "medium", "medium": "low", "low": "info"}


def registrable(host: str) -> str | None:
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None
    except ValueError:
        pass
    labels = host.split(".")
    keep = 3 if ".".join(labels[-2:]) in _BROAD_SUFFIXES else 2
    return ".".join(labels[-keep:]) if len(labels) >= keep else None


def _program_domains(ctx: BotContext) -> set[str]:
    return {d for d in (registrable(h) for h in ctx.guard.seed_domains() + ctx.guard.seed_hosts())
            if d}


def external_links(ctx: BotContext) -> list[dict]:
    """[{url, tag, pages}] for links from in-scope pages to other sites."""
    links = []
    for asset in db.get_assets(ctx.program_id, "external"):
        pages = [p for p in asset["data"].get("pages", {}) if ctx.in_scope_url(p)]
        if pages:
            links.append({"url": asset["value"], "tag": asset["data"].get("kind", "a"),
                          "pages": pages})
    return links


# =====================================================================
class BrokenLinkBot(Bot):
    id, department = "broken_links", DEPT

    async def run(self, ctx: BotContext) -> None:
        links = external_links(ctx)
        if not links:
            ctx.log("No links to other sites in the inventory. Run the Crawler bot first.")
            ctx.partial = True  # input missing: keep earlier cards
            return
        ours = _program_domains(ctx)
        domains: dict[str, list[dict]] = {}
        for link in links:
            domain = registrable(urlsplit(link["url"]).hostname or "")
            if domain and domain not in ours and domain not in WELL_KNOWN:
                domains.setdefault(domain, []).append(link)
        if not domains:
            ctx.log("Every linked domain is a well-known service or the program's own.")
            return
        registries = await self._bootstrap(ctx)
        if registries is None:
            ctx.log("Could not load IANA's list of registry servers; nothing checked.", "error")
            ctx.partial = True  # input missing: keep earlier cards
            return
        limit = int(ctx.options.get("thirdparty_max_domains", 200))
        checked = flagged = unknown = 0
        for domain, uses in sorted(domains.items())[:limit]:
            tld = domain.rsplit(".", 1)[-1]
            base = registries.get(tld)
            if base is None:
                unknown += 1
                ctx.asset("linkdomain", domain, {"registry": f"no RDAP service for .{tld}",
                                                 "links": len(uses)})
                continue
            ctx.allow_registry(urlsplit(base).hostname)
            response = await ctx.source(f"{base}domain/{quote(domain)}",
                                        headers={"Accept": "application/rdap+json"})
            checked += 1
            state, detail = self._state(response)
            ctx.asset("linkdomain", domain, {"registry": urlsplit(base).hostname, "state": state,
                                             "links": len(uses)})
            if state.startswith("unknown"):
                ctx.partial = True  # no usable answer: keep earlier cards
            if state not in ("not registered", "being deleted", "expired"):
                continue
            flagged += 1
            weight = max(TAG_WEIGHT.get(u["tag"], 1) for u in uses)
            severity = SEVERITY[weight] if state != "expired" else LOWER[SEVERITY[weight]]
            strongest = max(uses, key=lambda u: TAG_WEIGHT.get(u["tag"], 1))
            what = {"script": "loads a script from", "iframe": "embeds a frame from",
                    "link": "loads a resource from", "form": "submits a form to"}.get(
                strongest["tag"], "links to")
            ctx.finding(
                "broken_link_expired_domain", key=domain, severity=severity,
                title=f"Site {what} {domain}, which is {state}", target=strongest["pages"][0],
                detail=f"The registry says the domain is {state}{detail}. Whoever registers it "
                       "controls what this link serves" +
                       (" (a script from it runs inside the program's pages)"
                        if strongest["tag"] == "script" else "") +
                       ". Confirm by hand. Do not register the domain unless the program's "
                       "rules allow that kind of proof of concept.",
                evidence={"domain": domain, "registry_state": state,
                          "links": [f"{u['tag']}: {u['url']} (on {u['pages'][0]})" for u in uses[:8]],
                          "how_checked": f"RDAP query to {urlsplit(base).hostname}; the linked "
                                         "site itself was not contacted"})
        ctx.flush()
        ctx.log(f"{len(domains)} linked domains; {checked} asked at their registry, "
                f"{flagged} not registered or expiring"
                + (f", {unknown} on registries without RDAP (not checked)" if unknown else "")
                + (f"; {len(domains) - limit} over the limit, skipped" if len(domains) > limit else ""))

    async def _bootstrap(self, ctx: BotContext) -> dict[str, str] | None:
        response = await ctx.source("https://data.iana.org/rdap/dns.json")
        if response is None or response.status_code != 200:
            return None
        registries = {}
        for tlds, urls in response.json().get("services", []):
            https = [u if u.endswith("/") else u + "/" for u in urls if u.startswith("https://")]
            if https:
                for tld in tlds:
                    registries[tld.lower()] = https[0]
        return registries

    @staticmethod
    def _state(response) -> tuple[str, str]:
        if response is None:
            return "unknown (no answer)", ""
        if response.status_code == 404:
            return "not registered", ""
        if response.status_code != 200:
            return f"unknown (registry answered {response.status_code})", ""
        try:
            data = response.json()
        except ValueError:
            return "unknown (unreadable answer)", ""
        statuses = [str(s).lower() for s in data.get("status", [])]
        if any(s in statuses for s in ("pending delete", "redemption period")):
            return "being deleted", f" (status: {', '.join(statuses)})"
        for event in data.get("events", []):
            if event.get("eventAction") == "expiration":
                try:
                    when = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                except (KeyError, ValueError):
                    break
                if when < datetime.now(timezone.utc):
                    return "expired", f" (expired {when:%Y-%m-%d}, still in the registry)"
        return "registered", ""


# =====================================================================
RESERVED = {"about", "features", "pricing", "login", "join", "signup", "explore", "search",
            "settings", "share", "sharer", "sharer.php", "intent", "home", "hashtag", "i",
            "p", "reel", "reels", "explore", "watch", "embed", "plugins", "dialog", "events",
            "marketplace", "sponsors", "topics", "orgs", "enterprise", "help", "privacy",
            "terms", "legal", "policies", "tos", "contact", "jobs", "careers", "groups",
            "pages", "profile.php", "public", "status", "statuses", "playlist", "results"}
SOCIAL = [
    ("GitHub", re.compile(r"^(?:www\.)?github\.com$"), re.compile(r"^/([A-Za-z0-9-]{1,39})(?:/|$)")),
    ("GitLab", re.compile(r"^(?:www\.)?gitlab\.com$"), re.compile(r"^/([A-Za-z0-9_.-]{2,255})(?:/|$)")),
    ("X (Twitter)", re.compile(r"^(?:www\.|mobile\.)?(?:twitter|x)\.com$"), re.compile(r"^/@?([A-Za-z0-9_]{1,15})(?:/|$)")),
    ("Instagram", re.compile(r"^(?:www\.)?instagram\.com$"), re.compile(r"^/([A-Za-z0-9_.]{1,30})(?:/|$)")),
    ("Facebook", re.compile(r"^(?:www\.|m\.)?(?:facebook|fb)\.com$"), re.compile(r"^/([A-Za-z0-9.]{5,50})(?:/|$)")),
    ("LinkedIn", re.compile(r"^(?:[a-z]{2,3}\.|www\.)?linkedin\.com$"), re.compile(r"^/((?:company|in|school|showcase)/[A-Za-z0-9_-]{2,100})(?:/|$)")),
    ("YouTube", re.compile(r"^(?:www\.|m\.)?youtube\.com$"), re.compile(r"^/((?:@|c/|user/|channel/)[A-Za-z0-9_.-]{1,100})(?:/|$)")),
    ("TikTok", re.compile(r"^(?:www\.)?tiktok\.com$"), re.compile(r"^/(@[A-Za-z0-9_.]{2,24})(?:/|$)")),
    ("Medium", re.compile(r"^(?:www\.)?medium\.com$"), re.compile(r"^/(@[A-Za-z0-9_.-]{1,50})(?:/|$)")),
    ("Telegram", re.compile(r"^(?:www\.)?(?:t\.me|telegram\.me)$"), re.compile(r"^/([A-Za-z0-9_]{5,32})(?:/|$)")),
    ("Discord invite", re.compile(r"^(?:www\.)?(?:discord\.gg|discord\.com)$"), re.compile(r"^/(?:invite/)?([A-Za-z0-9-]{2,32})(?:/|$)")),
    ("Pinterest", re.compile(r"^(?:[a-z]{2}\.|www\.)?pinterest\.[a-z.]+$"), re.compile(r"^/([A-Za-z0-9_]{3,30})(?:/|$)")),
    ("Reddit", re.compile(r"^(?:www\.|old\.)?reddit\.com$"), re.compile(r"^/((?:r|u|user)/[A-Za-z0-9_-]{2,30})(?:/|$)")),
]


def social_handle(url: str) -> tuple[str, str] | None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    for platform, host_re, path_re in SOCIAL:
        if host_re.match(host):
            match = path_re.match(parts.path or "/")
            if match and match.group(1).lower().strip("@") not in RESERVED:
                return platform, match.group(1)
            return None
    return None


class SocialHandleBot(Bot):
    id, department = "social_handles", DEPT

    async def run(self, ctx: BotContext) -> None:
        links = external_links(ctx)
        handles: dict[tuple[str, str], list[dict]] = {}
        for link in links:
            found = social_handle(link["url"])
            if found:
                handles.setdefault(found, []).append(link)
        if not handles:
            ctx.log("No links to social profiles in the inventory.")
            return
        token = db.get_setting("github_token") or os.environ.get("GITHUB_TOKEN")
        github_ok, checked, missing, manual = True, 0, 0, 0
        for (platform, handle), uses in sorted(handles.items()):
            status = "not checked: no public API (check by hand)"
            if platform == "GitHub" and github_ok:
                headers = {"Accept": "application/vnd.github+json"}
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                response = await ctx.source(f"https://api.github.com/users/{quote(handle)}",
                                            headers=headers)
                if response is not None and response.status_code in (403, 429):
                    github_ok = False
                    ctx.log("GitHub API rate limit reached; remaining GitHub handles not checked.",
                            "warn")
                    status = "not checked: rate limit"
                    ctx.partial = True
                elif response is not None and response.status_code in (200, 404):
                    status = "exists" if response.status_code == 200 else "not found"
                else:
                    status = "not checked: no answer"
            elif platform == "GitLab":
                users = await ctx.source(f"https://gitlab.com/api/v4/users?username={quote(handle)}")
                if users is not None and users.status_code == 200 and users.json():
                    status = "exists"
                elif users is not None and users.status_code == 200:
                    group = await ctx.source(f"https://gitlab.com/api/v4/groups/{quote(handle, safe='')}")
                    status = ("exists" if group is not None and group.status_code == 200 else
                              "not found (or a private group)" if group is not None and
                              group.status_code == 404 else "not checked: no answer")
                else:
                    status = "not checked: no answer"
            if status.startswith("not checked: no public"):
                manual += 1
            else:
                checked += 1
            for link in uses:
                ctx.asset("social", link["url"], {"platform": platform, "handle": handle,
                                                  "status": status, "pages": link["pages"][:3]})
            if not status.startswith("not found"):
                continue
            missing += 1
            ctx.finding(
                "social_handle_unclaimed", key=f"{platform}|{handle.lower()}", severity="low",
                title=f"Linked {platform} account '{handle}' does not exist", target=uses[0]["pages"][0],
                detail=f"The site links to {platform} '{handle}', and {platform}'s public API "
                       "has no such account. Anyone could register the name and impersonate the "
                       "company behind an official link. Confirm on the platform. Only claim "
                       "the name if the program's rules allow it, and then without any content.",
                evidence={"link": uses[0]["url"], "linked_from": uses[0]["pages"][:5],
                          "api_answer": status})
        ctx.flush()
        ctx.log(f"{len(handles)} social handles linked: {checked} checked through public APIs, "
                f"{missing} not found, {manual} on platforms without a public API "
                "(listed under Inventory → Social links for a manual look)")


BOTS = {bot.id: bot for bot in (BrokenLinkBot(), SocialHandleBot())}
