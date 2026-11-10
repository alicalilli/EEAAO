"""Recon department: builds the inventory every later department works from.

Passive only. Bots read third-party data sources (certificate logs, passive
DNS, the Wayback Machine, GitHub search) and make ordinary GET requests to
in-scope sites, as a visitor's browser would. They never send payloads,
never guess paths (robots.txt, sitemap.xml and security.txt are published
standard locations), never submit forms and never request anything found
only in an archive.
"""
from __future__ import annotations

import asyncio
import gzip
import html
import json
import os
import re
from urllib.parse import quote, urlsplit
from urllib.robotparser import RobotFileParser

from .. import db
from ..scope import Target, _DEFAULT_PORTS
from .base import Bot, BotContext
from .extract import (SKIP_EXT, UNSAFE_LINK, endpoint, find_buckets, find_secrets,
                      fingerprint, hostnames_under, looks_internal,
                      normalize_url, origin, param_names, parse_html)
from .net import OutOfScope

_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


async def _limited(n: int, coros) -> list:
    semaphore = asyncio.Semaphore(n)

    async def one(coro):
        async with semaphore:
            return await coro
    return await asyncio.gather(*(one(c) for c in coros))


def _is_ip(host: str) -> bool:
    try:
        return Target.parse(host).ip is not None
    except Exception:
        return False


def known_hosts(ctx: BotContext) -> list[str]:
    """Scope seeds plus every inventoried host that is still in scope."""
    hosts = list(ctx.guard.seed_hosts())
    hosts += [a["value"] for a in db.get_assets(ctx.program_id, "host")]
    return [h for h in dict.fromkeys(hosts) if ctx.in_scope_host(h)]


# =====================================================================
class SubdomainBot(Bot):
    id, department = "subdomains", "recon"

    async def run(self, ctx: BotContext) -> None:
        for host in ctx.guard.seed_hosts():
            ctx.asset("host", host, {"sources": {"scope": 1}})
        domains = ctx.guard.seed_domains()
        if not domains:
            ctx.log("No wildcard entries in scope (like *.example.com), so there is "
                    "nothing to enumerate. Scope hosts were added to the inventory.")
            ctx.flush()
            return
        for domain in domains:
            if ctx.in_scope_host(domain):
                ctx.asset("host", domain, {"sources": {"scope": 1}})
            found: dict[str, set[str]] = {}
            for source, fetch in (("crt.sh", self._crtsh), ("certspotter", self._certspotter),
                                  ("otx", self._otx)):
                try:
                    names = await fetch(ctx, domain)
                except (ValueError, KeyError, TypeError) as exc:
                    ctx.log(f"{source}: could not read the answer for {domain} ({exc})", "warn")
                    continue
                if names is None:
                    ctx.log(f"{source}: no answer for {domain} (see request log)", "warn")
                    continue
                for name in names:
                    name = name.strip().lower().rstrip(".")
                    while name.startswith("*."):
                        name = name[2:]
                    if _HOST.match(name) and (name == domain or name.endswith("." + domain)):
                        found.setdefault(name, set()).add(source)
            kept = 0
            for name, sources in found.items():
                if ctx.in_scope_host(name):
                    kept += 1
                    ctx.asset("host", name, {"sources": {s: 1 for s in sources}})
            ctx.flush()
            ctx.log(f"{domain}: {len(found)} names found, {kept} in scope, "
                    f"{len(found) - kept} dropped as out of scope")

    async def _crtsh(self, ctx, domain):
        response = await ctx.source(f"https://crt.sh/?q={quote('%.' + domain)}&output=json",
                                    retries=2)
        if response is None or response.status_code != 200:
            return None
        names = []
        for row in response.json():
            names += str(row.get("name_value", "")).split("\n")
            names.append(str(row.get("common_name", "")))
        return names

    async def _certspotter(self, ctx, domain):
        names, after = [], None
        for _ in range(3):
            url = (f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}"
                   "&include_subdomains=true&expand=dns_names")
            if after:
                url += f"&after={quote(str(after))}"
            response = await ctx.source(url)
            if response is None or response.status_code != 200:
                return names or None
            rows = response.json()
            for row in rows:
                names += row.get("dns_names", [])
            if len(rows) < 100:
                break
            after = rows[-1]["id"]
        return names

    async def _otx(self, ctx, domain):
        response = await ctx.source(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns")
        if response is None or response.status_code != 200:
            return None
        return [row.get("hostname", "") for row in response.json().get("passive_dns", [])]


# =====================================================================
class DnsBot(Bot):
    id, department = "dns", "recon"

    async def run(self, ctx: BotContext) -> None:
        hosts = [h for h in known_hosts(ctx) if not _is_ip(h)]
        if not hosts:
            ctx.log("No host names to look up (the scope only lists IP addresses, or the "
                    "Subdomain bot has not run yet).")
            return
        # Mail and name-server records matter for whole domains, not every subdomain.
        roots = set(ctx.guard.seed_domains()) | set(ctx.guard.seed_hosts())
        stats = {"resolves": 0, "dead": 0}

        async def one(host: str):
            records = {}
            answer = await ctx.dns(host, "A")
            records["A"] = answer.records
            records["CNAME"] = answer.cnames
            status = answer.status
            if not answer.records and not answer.cnames:
                # A dangling CNAME answers NXDOMAIN for A but still exists.
                cname = await ctx.dns(host, "CNAME")
                records["CNAME"] = cname.records
            if host in roots:
                for rtype in ("MX", "TXT", "NS"):
                    records[rtype] = (await ctx.dns(host, rtype)).records
            resolves = bool(records["A"])
            stats["resolves" if resolves else "dead"] += 1
            ctx.asset("dns", host, {"status": status, "records": records})
            ctx.asset("host", host, {"resolves": resolves, "ips": records["A"],
                                     "cname": records["CNAME"]})

        ctx.log(f"Looking up {len(hosts)} names")
        await _limited(10, [one(h) for h in hosts])
        ctx.flush()
        ctx.log(f"{stats['resolves']} names resolve, {stats['dead']} do not")


# =====================================================================
def start_urls(ctx: BotContext, host: str) -> list[str]:
    """Where a visitor would start on this host, limited to what scope allows:
    the root page, or the scoped path/port if the rule names one."""
    target = Target.parse(host)
    urls = []
    for rule in ctx.guard.allow:
        if not rule.host_matches(target):
            continue
        for scheme in ([rule.scheme] if rule.scheme else ["https", "http"]):
            port = rule.port
            shown = f"[{host}]" if ":" in host else host
            netloc = shown if port in (None, _DEFAULT_PORTS[scheme]) else f"{shown}:{port}"
            urls.append(f"{scheme}://{netloc}{rule.path}")
    return [u for u in dict.fromkeys(urls) if ctx.in_scope_url(u)]


class LiveHostBot(Bot):
    id, department = "livehosts", "recon"

    async def run(self, ctx: BotContext) -> None:
        dns_state = {a["value"]: a["data"].get("resolves")
                     for a in db.get_assets(ctx.program_id, "host")}
        hosts = [h for h in known_hosts(ctx) if dns_state.get(h) is not False]
        if not hosts:
            ctx.log("No resolving hosts in the inventory. Run the Subdomain and DNS bots first.")
            return
        live = 0

        async def one(host: str):
            nonlocal live
            answered = False
            for url in start_urls(ctx, host):
                fetched = await ctx.fetch(url)
                if fetched is None:
                    continue
                answered = True
                ctx.save_response(fetched)
                text = fetched.text() if "html" in fetched.content_type else ""
                page = parse_html(text, fetched.final_url) if text else {"title": "", "generator": ""}
                tech = fingerprint(fetched.headers, text, page["generator"])
                ctx.asset("site", url, {
                    "status": fetched.status, "final_url": fetched.final_url,
                    "title": page["title"], "server": fetched.header("server") or "",
                    "tech": tech, "redirects": fetched.redirects,
                    "blocked_redirect": fetched.blocked_redirect,
                    "content_type": fetched.content_type[:100]})
                ctx.asset("host", host, {"live": True, "tech": {t: 1 for t in tech}})
            if answered:
                live += 1
            else:
                ctx.asset("host", host, {"live": False})

        ctx.log(f"Checking {len(hosts)} hosts")
        await _limited(5, [one(h) for h in hosts])
        ctx.flush()
        ctx.log(f"{live} of {len(hosts)} hosts answered")


def live_origins(ctx: BotContext) -> list[str]:
    origins = []
    for site in db.get_assets(ctx.program_id, "site"):
        data = site["data"]
        if data.get("status") and data["status"] < 500:
            for url in (data.get("final_url") or site["value"], site["value"]):
                if ctx.in_scope_url(origin(url) + "/"):
                    origins.append(origin(url))
                    break
    return list(dict.fromkeys(origins))


# =====================================================================
def _looks_text(fetched) -> bool:
    return (fetched is not None and fetched.status == 200 and "html" not in fetched.content_type
            and b"<html" not in fetched.body[:2000].lower())


class PublicFilesBot(Bot):
    id, department = "publicfiles", "recon"

    async def run(self, ctx: BotContext) -> None:
        origins = live_origins(ctx)
        if not origins:
            ctx.log("No live sites yet. Run the Live host bot first.")
            return
        for site in origins:
            try:
                await self._one(ctx, site)
            except OutOfScope as exc:
                ctx.log(f"Skipped: {exc}", "warn")
            ctx.flush()

    async def _one(self, ctx: BotContext, site: str) -> None:
        sitemaps = []
        robots_url = site + "/robots.txt"
        if ctx.in_scope_url(robots_url):
            robots = await ctx.fetch(robots_url, follow=False)
            if _looks_text(robots):
                ctx.save_response(robots)
                text = robots.text()
                paths = 0
                for line in text.splitlines():
                    field, _, value = line.partition(":")
                    field, value = field.strip().lower(), value.split("#")[0].strip()
                    if field == "sitemap":
                        url = normalize_url(value)
                        if url and ctx.in_scope_url(url):
                            sitemaps.append(url)
                    elif field in ("disallow", "allow") and value.startswith("/"):
                        path = value.split("*")[0].rstrip("$")
                        url = normalize_url(site + path)
                        if url and ctx.in_scope_url(url):
                            paths += 1
                            ctx.asset("url", url, {"sources": {"robots": 1}})
                ctx.asset("publicfile", robots_url, {"kind": "robots.txt", "bytes": len(robots.body),
                                                     "paths": paths, "sitemaps": len(sitemaps)})
                ctx.log(f"{robots_url}: {paths} paths, {len(sitemaps)} sitemaps listed")

        default_map = site + "/sitemap.xml"
        if default_map not in sitemaps and ctx.in_scope_url(default_map):
            sitemaps.insert(0, default_map)
        seen, urls = set(), 0
        while sitemaps and len(seen) < 10 and urls < 5000:
            url = sitemaps.pop(0)
            if url in seen:
                continue
            seen.add(url)
            fetched = await ctx.fetch(url, follow=False)
            if fetched is None or fetched.status != 200:
                continue
            body = fetched.body
            if body[:2] == b"\x1f\x8b":
                try:
                    body = gzip.decompress(body)[:20_000_000]
                except OSError:
                    continue
            text = body.decode("utf-8", errors="replace")
            if "<urlset" not in text and "<sitemapindex" not in text:
                continue
            ctx.save_response(fetched)
            locs = [html.unescape(m) for m in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", text)]
            nested = "<sitemapindex" in text
            count = 0
            for loc in locs:
                loc = normalize_url(loc)
                if not loc or not ctx.in_scope_url(loc):
                    continue
                if nested:
                    sitemaps.append(loc)
                elif urls < 5000:
                    urls += 1
                    count += 1
                    ctx.asset("url", loc, {"sources": {"sitemap": 1}})
            ctx.asset("publicfile", url, {"kind": "sitemap index" if nested else "sitemap",
                                          "entries": len(locs)})
            ctx.log(f"{url}: {len(locs)} entries" + ("" if nested else f", {count} in scope"))

        for path in ("/.well-known/security.txt", "/security.txt"):
            url = site + path
            if not ctx.in_scope_url(url):
                continue
            fetched = await ctx.fetch(url, follow=False)
            if _looks_text(fetched) and re.search(rb"(?im)^\s*contact\s*:", fetched.body):
                ctx.save_response(fetched)
                text = fetched.text()
                fields = {}
                for line in text.splitlines():
                    name, sep, value = line.partition(":")
                    if sep and name.strip() and not name.startswith("#"):
                        fields.setdefault(name.strip().lower(), []).append(value.strip()[:300])
                ctx.asset("publicfile", url, {"kind": "security.txt", "fields": fields})
                ctx.log(f"{url}: security.txt found")
                break


# =====================================================================
class CrawlerBot(Bot):
    id, department = "crawler", "recon"

    async def run(self, ctx: BotContext) -> None:
        opt = ctx.options
        per_host = int(opt.get("crawl_pages_per_host", 40))
        max_pages = int(opt.get("crawl_max_pages", 300))
        max_depth = int(opt.get("crawl_depth", 3))
        max_js = int(opt.get("crawl_max_js", 150))
        respect_robots = bool(opt.get("crawl_respect_robots", True))

        seeds = []
        for site in db.get_assets(ctx.program_id, "site"):
            if site["data"].get("status", 999) < 400:
                seeds.append(site["data"].get("final_url") or site["value"])
        sitemap_seeds: dict[str, int] = {}
        for url in db.get_assets(ctx.program_id, "url"):
            if "sitemap" in url["data"].get("sources", {}):
                host = urlsplit(url["value"]).netloc
                if sitemap_seeds.get(host, 0) < 20:
                    sitemap_seeds[host] = sitemap_seeds.get(host, 0) + 1
                    seeds.append(url["value"])
        if not seeds:
            ctx.log("No live sites yet. Run the Live host bot first.")
            return

        robots: dict[str, RobotFileParser | None] = {}

        def robots_allow(url: str) -> bool:
            if not respect_robots:
                return True
            site = origin(url)
            if site not in robots:
                stored = db.get_response(ctx.program_id, site + "/robots.txt")
                parser = None
                if stored and stored["status"] == 200 and stored["body"]:
                    parser = RobotFileParser()
                    parser.parse(bytes(stored["body"]).decode("utf-8", "replace").splitlines())
                robots[site] = parser
            parser = robots[site]
            return parser is None or parser.can_fetch("*", url)

        queue = [(normalize_url(s), 0) for s in seeds]
        queued = {u for u, _ in queue if u}
        pages_by_host: dict[str, int] = {}
        scripts: dict[str, None] = {}
        external_count: dict[str, int] = {}
        pages = skipped_robots = 0

        while queue and pages < max_pages:
            url, depth = queue.pop(0)
            if not url or not ctx.in_scope_url(url):
                continue
            host = urlsplit(url).netloc
            if pages_by_host.get(host, 0) >= per_host:
                continue
            if not robots_allow(url):
                skipped_robots += 1
                continue
            fetched = await ctx.fetch(url)
            pages += 1
            pages_by_host[host] = pages_by_host.get(host, 0) + 1
            if fetched is None:
                continue
            ctx.save_response(fetched)
            is_html = "html" in fetched.content_type
            page = parse_html(fetched.text(), fetched.final_url) if is_html else None
            ctx.asset("url", url, {"sources": {"crawler": 1}, "status": fetched.status,
                                   "content_type": fetched.content_type[:100],
                                   "title": page["title"] if page else ""})
            for name in param_names(url):
                ctx.asset("param", f"{endpoint(url)} ? {name}", {"sources": {"crawler": 1},
                                                                  "example": url})
            if fetched.final_url != url and ctx.in_scope_url(fetched.final_url):
                ctx.asset("url", fetched.final_url, {"sources": {"crawler": 1}})
            if not page:
                continue

            for form in page["forms"]:
                action = form["action"]
                if not ctx.in_scope_url(action):
                    ctx.asset("external", action, {"pages": {url: 1}, "kind": "form"})
                    continue
                names = [i["name"] for i in form["inputs"]]
                ctx.asset("form", f"{form['method'].upper()} {action}",
                          {"inputs": {i["name"]: i["type"] for i in form["inputs"]},
                           "found_on": url})
                for name in names:
                    ctx.asset("param", f"{endpoint(action)} ? {name}",
                              {"sources": {"form": 1}, "method": form["method"]})

            for tag, link in page["links"]:
                if not ctx.in_scope_url(link):
                    seen = external_count.get(link, 0)
                    if seen < 3:
                        external_count[link] = seen + 1
                        ctx.asset("external", link, {"pages": {url: 1}, "kind": tag})
                    continue
                if tag == "script":
                    scripts.setdefault(link, None)
                    ctx.asset("js", link, {"sources": {"crawler": 1}, "pages": {url: 1}})
                    continue
                ctx.asset("url", link, {"sources": {"crawler": 1}})
                for name in param_names(link):
                    ctx.asset("param", f"{endpoint(link)} ? {name}",
                              {"sources": {"crawler": 1}, "example": link})
                if (tag in ("a", "area", "iframe", "frame", "meta") and depth < max_depth
                        and link not in queued and not SKIP_EXT.search(urlsplit(link).path)
                        and not UNSAFE_LINK.search(link)):
                    queued.add(link)
                    queue.append((link, depth + 1))
            ctx.flush()

        ctx.log(f"Visited {pages} pages on {len(pages_by_host)} hosts"
                + (f"; {skipped_robots} skipped because robots.txt asks" if skipped_robots else ""))

        fetched_js = 0
        for js in list(scripts)[:max_js]:
            if not robots_allow(js):
                continue
            result = await ctx.fetch(js)
            if result is not None and result.status == 200:
                fetched_js += 1
                ctx.save_response(result)
                ctx.asset("js", js, {"status": result.status, "bytes": len(result.body)})
        ctx.flush()
        ctx.log(f"Downloaded {fetched_js} of {len(scripts)} JavaScript files")


# =====================================================================
INTERESTING_FILE = re.compile(
    r"\.(sql|bak|backup|old|orig|swp|env|log|zip|tar|tgz|gz|7z|rar|config|conf|cfg|ini|"
    r"ya?ml|key|pem|p12|pfx|db|sqlite3?|dump|csv|xlsx?)$|/\.git/|/\.env|wp-config|phpinfo",
    re.I)


class ArchiveBot(Bot):
    id, department = "archive", "recon"

    async def run(self, ctx: BotContext) -> None:
        limit = int(ctx.options.get("archive_limit", 50_000))
        domains = ctx.guard.seed_domains()
        queries = [(d, "domain") for d in domains]
        for host in ctx.guard.seed_hosts():
            if not _is_ip(host) and not any(host == d or host.endswith("." + d) for d in domains):
                queries.append((host, "host"))
        if not queries:
            ctx.log("Scope has no host names to look up in the archive.")
            return
        lead_budget = int(ctx.options.get("archive_max_leads", 200))
        for name, match_type in queries:
            response = await ctx.source(
                f"https://web.archive.org/cdx/search/cdx?url={quote(name)}&matchType={match_type}"
                f"&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&output=json"
                f"&limit={limit}", retries=2)
            if response is None or response.status_code != 200:
                ctx.log(f"Wayback Machine gave no answer for {name}", "warn")
                continue
            try:
                rows = response.json() if response.content.strip() else []
            except json.JSONDecodeError:
                ctx.log(f"Wayback Machine answer for {name} was not JSON", "warn")
                continue
            kept = dropped = params = 0
            for row in rows[1:]:
                if len(row) < 4:
                    continue
                url = normalize_url(row[0])
                if not url or not ctx.in_scope_url(url):
                    dropped += 1
                    continue
                kept += 1
                ctx.asset("url", url, {"sources": {"wayback": 1}, "archived": {
                    "timestamp": row[1], "status": row[2], "mime": row[3]}})
                for pname in param_names(url):
                    params += 1
                    ctx.asset("param", f"{endpoint(url)} ? {pname}",
                              {"sources": {"wayback": 1}, "example": url})
                path = urlsplit(url).path
                if path.lower().endswith(".js"):
                    ctx.asset("js", endpoint(url), {"sources": {"wayback": 1}})
                if INTERESTING_FILE.search(path) and lead_budget > 0:
                    if ctx.lead("archive_interesting_file", key=endpoint(url),
                                title=f"Archived file looks sensitive: {path.rsplit('/', 1)[-1]}",
                                target=url, severity="info",
                                detail="The Wayback Machine captured this URL. The bot did not "
                                       "request it. Check by hand, within program rules, whether "
                                       "it is still served.",
                                evidence={"archived_at": row[1], "archived_status": row[2],
                                          "mime": row[3],
                                          "snapshot": f"https://web.archive.org/web/{row[1]}/{row[0]}"}):
                        lead_budget -= 1
            ctx.flush()
            ctx.log(f"{name}: {kept} archived URLs in scope ({params} parameters), "
                    f"{dropped} out of scope dropped")


# =====================================================================
class GitHubBot(Bot):
    id, department = "github", "recon"
    KEYWORDS = ("", "password", "api_key", "secret", "token")

    async def run(self, ctx: BotContext) -> None:
        token = db.get_setting("github_token") or os.environ.get("GITHUB_TOKEN")
        if not token:
            ctx.log("No GitHub token set (Settings, or the GITHUB_TOKEN environment "
                    "variable). GitHub code search requires one; skipping.", "warn")
            return
        names = ctx.guard.seed_domains() + [h for h in ctx.guard.seed_hosts() if not _is_ip(h)]
        names = [n for i, n in enumerate(names)
                 if not any(n.endswith("." + other) for other in names[:i] + names[i + 1:])]
        budget = int(ctx.options.get("github_max_queries", 10))
        headers = {"Authorization": f"Bearer {token}",
                   "Accept": "application/vnd.github.text-match+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        results = secrets = 0
        for name in names:
            for word in self.KEYWORDS:
                if budget <= 0:
                    break
                budget -= 1
                query = f'"{name}" {word}'.strip()
                response = await ctx.source(
                    f"https://api.github.com/search/code?q={quote(query)}&per_page=50",
                    headers=headers)
                if response is None:
                    continue
                if response.status_code == 401:
                    ctx.log("GitHub rejected the token (401). Check it in Settings.", "error")
                    return
                if response.status_code in (403, 429):
                    ctx.log("GitHub rate limit reached; stopping early.", "warn")
                    ctx.flush()
                    return
                if response.status_code != 200:
                    ctx.log(f"GitHub search for {query} answered {response.status_code}", "warn")
                    continue
                for item in response.json().get("items", []):
                    results += 1
                    secrets += self._item(ctx, item, name, query)
                ctx.flush()
        ctx.log(f"{results} code results reviewed, {secrets} possible secrets flagged")

    def _item(self, ctx: BotContext, item: dict, name: str, query: str) -> int:
        repo = item.get("repository", {}).get("full_name", "?")
        url = item.get("html_url", "")
        path = item.get("path", "")
        ctx.asset("github", url, {"repo": repo, "path": path, "query": query})
        flagged = 0
        for match in item.get("text_matches", []):
            fragment = match.get("fragment", "")
            for secret in find_secrets(fragment):
                snippet = fragment.replace(secret["raw"], secret["masked"])[:600]
                if ctx.finding(
                        "github_secret", key=f"{url}|{secret['masked']}",
                        title=f"Possible {secret['label']} in {repo}", target=url,
                        severity=secret["severity"],
                        detail=f"Public code mentioning {name} contains what looks like a "
                               f"{secret['label']}. Not verified: the bot never uses or tests "
                               "credentials. Confirm the repository relates to the program and "
                               "that the policy accepts third-party leaks before reporting.",
                        evidence={"repository": repo, "file": path, "link": url,
                                  "match": secret["masked"], "snippet": snippet,
                                  "search": query}):
                    flagged += 1
            for host in hostnames_under(fragment, name):
                if ctx.in_scope_host(host):
                    ctx.asset("host", host, {"sources": {"github": 1}})
                if looks_internal(host):
                    ctx.lead("github_internal_url", key=f"{host}|{repo}",
                             title=f"Internal-looking host {host} in {repo}", target=url,
                             detail="Public code names a host that looks internal. Useful "
                                    "context for manual recon; nothing was requested.",
                             evidence={"host": host, "repository": repo, "file": path,
                                       "snippet": fragment[:400]})
        return flagged


# =====================================================================
class BucketBot(Bot):
    id, department = "buckets", "recon"

    async def run(self, ctx: BotContext) -> None:
        seen: dict[tuple[str, str], list[str]] = {}
        matched: dict[tuple[str, str], str] = {}

        def note(text: str, where: str):
            for provider, name, snippet in find_buckets(text):
                places = seen.setdefault((provider, name), [])
                matched.setdefault((provider, name), snippet)
                if where not in places and len(places) < 5:
                    places.append(where)

        scanned = 0
        for response in db.iter_responses(ctx.program_id):
            if response["body"]:
                scanned += 1
                note(bytes(response["body"]).decode("utf-8", "replace"), response["url"])
        for kind in ("url", "external", "js"):
            for asset in db.get_assets(ctx.program_id, kind):
                note(asset["value"], asset["value"])

        for (provider, name), places in seen.items():
            ctx.asset("bucket", f"{provider}: {name}",
                      {"provider": provider, "name": name, "seen_in": {p: 1 for p in places}})
            ctx.lead("bucket_reference", key=f"{provider}|{name}",
                     title=f"{provider} bucket '{name}' referenced", target=places[0],
                     detail="The site refers to this storage bucket. The bot did not contact "
                            "it. Check by hand who owns it and whether bucket issues are in "
                            "scope before testing anything.",
                     evidence={"provider": provider, "bucket": name, "seen_in": places,
                               "match": matched[(provider, name)]})
        ctx.flush()
        ctx.log(f"Scanned {scanned} stored responses; {len(seen)} buckets referenced")


BOTS = {bot.id: bot for bot in (SubdomainBot(), DnsBot(), LiveHostBot(), PublicFilesBot(),
                                CrawlerBot(), ArchiveBot(), GitHubBot(), BucketBot())}
