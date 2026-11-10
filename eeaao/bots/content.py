"""Content and JavaScript department.

Works from pages and JavaScript the crawler already stored. Two bots make
requests, and only for things the site itself points to:
  Source map bot   - GETs a .map file only when a stored JavaScript file names
                     it (sourceMappingURL / SourceMap header). Never guesses.
  Outdated library - asks the OSV vulnerability database (api.osv.dev) about
                     library versions. Nothing is sent to the target.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from .. import db
from .base import Bot, BotContext
from .extract import (endpoint, find_secrets, hostnames_under, is_private_ip,
                      looks_internal, normalize_url)
from .stored import Page, no_pages_message, pages, responses

DEPT = "content"


def scripts(ctx: BotContext) -> list[Page]:
    """Stored JavaScript files (2xx)."""
    return [p for p in pages(ctx)
            if "javascript" in p.content_type or "ecmascript" in p.content_type
            or p.path.lower().endswith((".js", ".mjs"))]


def _snippet(text: str, start: int, end: int, replace: dict[str, str] | None = None) -> str:
    piece = text[max(0, start - 80):end + 80].replace("\n", " ").strip()
    for raw, masked in (replace or {}).items():
        piece = piece.replace(raw, masked)
    return piece[:240]


# =====================================================================
class SecretsBot(Bot):
    id, department = "secrets", DEPT

    NOTES = {
        "Google API key": ("info", "Google API keys in front-end code are often meant to be "
                                   "public (Maps, Firebase). It only matters if the key is "
                                   "unrestricted and enabled for paid or sensitive APIs; "
                                   "checking that means using the key, which v1 never does."),
        "JSON Web Token": ("low", "A token embedded in a public file. Decode it (locally) to "
                                  "see what it grants and whether it has expired."),
        "Hard-coded credential": ("info", "Matched a password/secret assignment. Often a "
                                          "placeholder or test value: read the context."),
    }

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        sources = scripts(ctx) + [p for p in pages(ctx) if p.is_html]
        found = 0
        for page in sources:
            text = page.text
            found_here = find_secrets(text)
            masks = {s["raw"]: s["masked"] for s in found_here}  # mask every secret in snippets
            for secret in found_here:
                severity, note = self.NOTES.get(secret["label"], (secret["severity"], ""))
                at = text.find(secret["raw"])
                if ctx.finding(
                        "js_secret", key=f"{endpoint(page.url)}|{secret['masked']}",
                        severity=severity,
                        title=f"Possible {secret['label']} in {'JavaScript' if not page.is_html else 'page'}",
                        target=page.url,
                        detail=(note + " " if note else "") +
                               "Not verified: the bot never uses or tests credentials. Confirm "
                               "what it is and whether it is meant to be public before reporting.",
                        evidence={"file": page.url, "match": secret["masked"],
                                  "context": _snippet(text, at, at + len(secret["raw"]), masks),
                                  "fetched_at": page.fetched_at}):
                    found += 1
        ctx.log(f"Scanned {len(sources)} files; {found} new possible secrets")


# =====================================================================
_PATH = re.compile(r"""["'`](/(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_\-./{}:%]{1,200}(?:\?[^"'`\s<>]{0,200})?)["'`]""")
_FULL_URL = re.compile(r"""https?://[A-Za-z0-9.-]+(?::\d{2,5})?(?:/[^\s"'`<>()\\]{0,300})?""")
_IP_CONTEXT = re.compile(r"""(?:["'/@=]|https?://)((?:\d{1,3}\.){3}\d{1,3})(?::\d{2,5})?(?=[/"':])""")
_INTERNAL_NAME = re.compile(
    r"""(?:["'`@]|//)((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:local|internal|corp|lan|intranet))"""
    r"""(?=["'`/:?#])""", re.I)
_ASSET_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|map|mp4|webm)(?:\?|$)", re.I)


class EndpointsBot(Bot):
    id, department = "endpoints", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        roots = ctx.guard.seed_domains() + [h for h in ctx.guard.seed_hosts()]
        files = scripts(ctx)
        if not files:
            ctx.log("No JavaScript files stored. Run the Crawler bot first.")
            ctx.partial = True  # input missing: keep earlier cards
            return
        endpoints = hosts_flagged = ips_flagged = 0
        for page in files:
            text = page.text
            seen: set[str] = set()
            for match in _PATH.finditer(text):
                path = match.group(1)
                if path.startswith("//") or _ASSET_EXT.search(path) or len(seen) >= 500:
                    continue
                url = normalize_url(urljoin(page.url, path))
                if url and url not in seen and ctx.in_scope_url(url):
                    seen.add(url)
                    ctx.asset("endpoint", url, {"from": {page.url: 1}})
            for match in _FULL_URL.finditer(text):
                url = normalize_url(match.group(0).rstrip(".,;"))
                if url and url not in seen and len(seen) < 500 and ctx.in_scope_url(url) \
                        and not _ASSET_EXT.search(url):
                    seen.add(url)
                    ctx.asset("endpoint", url, {"from": {page.url: 1}})
            endpoints += len(seen)

            hosts: dict[str, int] = {}
            lowered = text.lower()
            for root in roots:
                for found in hostnames_under(text, root):
                    hosts.setdefault(found, lowered.find(found))
            # Names on internal-only suffixes count only inside a string or URL.
            # In minified code "e.local" is far more often a property of a
            # variable than a hostname.
            for match in _INTERNAL_NAME.finditer(text):
                hosts.setdefault(match.group(1).lower(), match.start(1))
            for host, at in sorted(hosts.items()):
                if ctx.guard.check_host_automated(host).reason == "Explicitly out of scope.":
                    continue  # the program asked us to leave it alone entirely
                if ctx.in_scope_host(host):
                    ctx.asset("host", host, {"sources": {"javascript": 1}})
                if looks_internal(host):
                    if ctx.finding(
                            "internal_host_disclosure", key=f"{host}", severity="info",
                            title=f"Internal-looking host {host} named in JavaScript",
                            target=page.url,
                            detail="Public JavaScript names a host that looks internal (staging, "
                                   "admin, corp...). Useful for manual recon; on its own it is "
                                   "rarely a reportable issue.",
                            evidence={"host": host, "file": page.url,
                                      "context": _snippet(text, at, at + len(host))}):
                        hosts_flagged += 1

            for match in _IP_CONTEXT.finditer(text):
                ip = match.group(1)
                if not is_private_ip(ip) or ip.startswith(("127.", "0.")) or ip == "255.255.255.255":
                    continue
                if ctx.finding(
                        "internal_ip_disclosure", key=f"{ip}|{endpoint(page.url)}", severity="info",
                        title=f"Private IP address {ip} in JavaScript", target=page.url,
                        detail="Reveals part of the internal network layout. Informational "
                               "unless combined with something else (SSRF, VPN access).",
                        evidence={"ip": ip, "file": page.url,
                                  "context": _snippet(text, match.start(1), match.end(1))}):
                    ips_flagged += 1
        ctx.flush()
        ctx.log(f"{len(files)} JavaScript files: {endpoints} in-scope endpoints, "
                f"{hosts_flagged} internal hosts, {ips_flagged} private IPs")


# =====================================================================
_MAP_REF = re.compile(r"[#@]\s*sourceMappingURL\s*=\s*(\S+)")


class SourceMapBot(Bot):
    id, department = "sourcemaps", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        limit = int(ctx.options.get("sourcemap_max", 50))
        referenced: dict[str, str] = {}
        for page in scripts(ctx):
            ref = page.header("sourcemap") or page.header("x-sourcemap")
            if not ref:
                matches = _MAP_REF.findall(page.text[-2000:])
                ref = matches[-1] if matches else None
            if ref and not ref.startswith("data:"):
                url = normalize_url(urljoin(page.url, ref))
                if url:
                    referenced.setdefault(url, page.url)
        if not referenced:
            ctx.log("No stored JavaScript file references a source map.")
            return
        exposed = skipped = 0
        for url, js in list(referenced.items())[:limit]:
            if not ctx.in_scope_url(url):
                skipped += 1
                continue
            fetched = await ctx.fetch(url, follow=False)
            if fetched is None:
                ctx.partial = True  # network trouble, not an answer
            if fetched is None or fetched.status != 200:
                ctx.asset("sourcemap", url, {"status": fetched.status if fetched else None,
                                             "referenced_by": js})
                continue
            try:
                data = json.loads(fetched.body.decode("utf-8", "replace"))
            except ValueError:
                continue
            if not isinstance(data, dict) or "mappings" not in data:
                continue
            sources = [str(s) for s in data.get("sources", [])][:2000]
            with_content = bool(data.get("sourcesContent"))
            exposed += 1
            ctx.asset("sourcemap", url, {"status": 200, "sources": len(sources),
                                         "has_source_code": with_content, "referenced_by": js})
            ctx.finding(
                "sourcemap_exposed", key=url, severity="low" if with_content else "info",
                title=f"Public source map{' with original source code' if with_content else ''}",
                target=url,
                detail="The minified JavaScript points to this map and it is downloadable, so "
                       "the original source can be rebuilt. Look through it for hidden "
                       "endpoints, comments and secrets. Many programs only accept it when "
                       "the recovered source reveals something sensitive.",
                evidence={"referenced_by": js, "files_in_map": len(sources),
                          "includes_source_code": with_content,
                          "sample_files": sources[:10] or None})
        ctx.flush()
        ctx.log(f"{len(referenced)} source maps referenced; {exposed} downloadable"
                + (f"; {skipped} out of scope, not requested" if skipped else ""))


# =====================================================================
DEBUG_PATTERNS = [
    ("Django debug page", "low", re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>|DEBUG = True</code> in your Django settings")),
    ("Laravel / Whoops debug page", "low", re.compile(r"Whoops! There was an error|Illuminate\\[A-Za-z\\]+Exception|ignition-|window\.ignite")),
    ("Rails exception page", "low", re.compile(r"Action Controller: Exception caught|<h1>Routing Error</h1>")),
    ("ASP.NET detailed error", "low", re.compile(r"Server Error in '/[^']*' Application|<b>\s*Stack Trace:\s*</b>|\[HttpException\]")),
    ("Symfony debug toolbar/profiler", "low", re.compile(r"sf-toolbar|/_profiler/|Symfony Exception")),
    ("Python traceback", "low", re.compile(r"Traceback \(most recent call last\):")),
    ("Java stack trace", "low", re.compile(r"(?:Exception|Error)(?::[^\n<]{0,200})?\s*(?:<br\s*/?>|\n)\s*at [a-zA-Z_$][\w$]*(?:\.[\w$<>]+)+\([\w$]+\.java:\d+\)")),
    (".NET stack trace", "low", re.compile(r"\n\s+at [A-Z][\w.]+\.[\w<>`]+\([^)]*\) in [A-Za-z]:\\")),
    ("Node.js stack trace", "low", re.compile(r"\n\s+at [^\n(]+\((?:/|[A-Z]:\\)[^\n)]+\.js:\d+:\d+\)")),
    ("PHP error message", "low", re.compile(r"<b>(?:Fatal error|Warning|Notice|Parse error|Deprecated)</b>:\s.{0,300}? on line <b>\d+</b>")),
    ("SQL error message", "low", re.compile(r"You have an error in your SQL syntax|SQLSTATE\[[0-9A-Z]{5}\]|ORA-\d{5}:|PG::[A-Za-z]+Error|unterminated quoted string at or near|Microsoft OLE DB Provider for SQL Server", re.I)),
    ("Server file path", "info", re.compile(r"(?:/var/www/|/home/[a-z0-9_-]+/(?:public_html|www|app)|/usr/share/nginx/html|[A-Z]:\\inetpub\\|[A-Z]:\\Users\\[^\\\s<]+\\)[^\s\"'<]{1,200}")),
]
_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_COMMENT_WORDS = re.compile(r"\b(todo|fixme|hack|xxx|password|passwd|secret|api[_ -]?key|token|debug|"
                            r"internal|staging|admin|credentials?|remove before|temporary)\b", re.I)


class DebugBot(Bot):
    id, department = "debug", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        flagged = 0
        for page in responses(ctx):
            if not page.raw or not any(t in page.content_type for t in
                                       ("html", "text", "json", "xml")) and page.content_type:
                continue
            text = page.text
            for label, severity, pattern in DEBUG_PATTERNS:
                match = pattern.search(text)
                if not match:
                    continue
                secrets = {s["raw"]: s["masked"] for s in find_secrets(
                    text[max(0, match.start() - 200):match.end() + 200])}
                if ctx.finding(
                        "debug_info", key=f"{endpoint(page.url)}|{label}", severity=severity,
                        title=f"{label} in response", target=page.url,
                        detail="Seen in an ordinary response the crawler received (status "
                               f"{page.status}). Debug output can reveal code, paths, versions "
                               "and sometimes configuration or secrets: read the full response "
                               "in a browser and report what it actually exposes.",
                        evidence={"status": page.status,
                                  "context": _snippet(text, match.start(), match.end(), secrets),
                                  "fetched_at": page.fetched_at}):
                    flagged += 1
            if page.is_html:
                notes = []
                for comment in _COMMENT.findall(text):
                    comment = " ".join(comment.split())
                    if _COMMENT_WORDS.search(comment) and not comment.startswith(("[if", "<![endif")):
                        for raw, masked in {s["raw"]: s["masked"] for s in find_secrets(comment)}.items():
                            comment = comment.replace(raw, masked)
                        notes.append(comment[:200])
                if notes:
                    if ctx.finding(
                            "debug_info", key=f"{endpoint(page.url)}|comments", severity="info",
                            title="HTML comments mention sensitive-sounding words",
                            target=page.url,
                            detail="Developer comments left in the page. Usually harmless; "
                                   "occasionally they name hidden paths, accounts or keys.",
                            evidence={"comments": notes[:10]}):
                        flagged += 1
        ctx.log(f"{flagged} new debug/verbose-error results")


# =====================================================================
V = r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?)"  # 1.2.3 or 1.2.3-rc.1, never ".min"
LIBRARY_URL = [
    ("jquery", re.compile(rf"jquery[.-]{V}(?:\.min|\.slim)*\.js", re.I)),
    ("jquery-ui", re.compile(rf"jquery-ui[.-]{V}", re.I)),
    ("bootstrap", re.compile(rf"bootstrap[.-]{V}", re.I)),
    ("angular", re.compile(rf"angular(?:js)?[.-]{V}", re.I)),
    ("lodash", re.compile(rf"lodash[.-]{V}", re.I)),
    ("moment", re.compile(rf"moment[.-]{V}", re.I)),
]
CDN_NPM = re.compile(rf"(?:cdn\.jsdelivr\.net/npm|unpkg\.com)/((?:@[\w.-]+/)?[\w.-]+)@{V}/", re.I)
CDNJS = re.compile(rf"cdnjs\.cloudflare\.com/ajax/libs/([\w.-]+)/{V}/", re.I)
GOOGLE_LIBS = re.compile(rf"ajax\.googleapis\.com/ajax/libs/([\w.-]+)/{V}/", re.I)
CDN_NAMES = {"angular.js": "angular", "angularjs": "angular", "jqueryui": "jquery-ui",
             "twitter-bootstrap": "bootstrap", "moment.js": "moment", "vue": "vue",
             "underscore.js": "underscore", "handlebars.js": "handlebars",
             "knockout": "knockout", "dompurify": "dompurify"}
LIBRARY_BANNER = [
    ("jquery", re.compile(rf"jQuery (?:JavaScript Library )?v{V}")),
    ("jquery-ui", re.compile(rf"jQuery UI - v{V}")),
    ("angular", re.compile(rf"AngularJS v{V}")),
    ("bootstrap", re.compile(rf"Bootstrap v{V}")),
    ("vue", re.compile(rf"Vue\.js v{V}")),
    ("moment", re.compile(rf"//! version : {V}")),
    ("underscore", re.compile(rf"Underscore\.js {V}")),
    ("handlebars", re.compile(rf"Handlebars\.VERSION\s*=\s*[\"']{V}")),
    ("dompurify", re.compile(rf"DOMPurify {V}")),
    ("knockout", re.compile(rf"Knockout JavaScript library v{V}")),
    ("lodash", re.compile(rf"\bVERSION\s*=\s*['\"]{V}['\"][\s\S]{{0,400}}lodash|lodash[\s\S]{{0,400}}\bVERSION\s*=\s*['\"]{V}['\"]")),
]
GH_SEVERITY = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}


def detect_libraries(urls: list[str], files: list[Page]) -> dict[tuple[str, str], set[str]]:
    """(npm name, version) -> where it was seen"""
    found: dict[tuple[str, str], set[str]] = {}
    for url in urls:
        for regex, mapper in ((CDN_NPM, lambda n: n.lower()),
                              (CDNJS, lambda n: CDN_NAMES.get(n.lower(), n.lower())),
                              (GOOGLE_LIBS, lambda n: CDN_NAMES.get(n.lower(), n.lower()))):
            match = regex.search(url)
            if match:
                found.setdefault((mapper(match.group(1)), match.group(2)), set()).add(url)
                break
        else:
            for name, regex in LIBRARY_URL:
                match = regex.search(urlsplit(url).path)
                if match:
                    found.setdefault((name, match.group(1)), set()).add(url)
                    break
    for page in files:
        head = page.text[:4000]
        for name, regex in LIBRARY_BANNER:
            match = regex.search(head if name != "lodash" else page.text[:200_000])
            if match:
                version = next(g for g in match.groups() if g)
                found.setdefault((name, version), set()).add(page.url)
    return found


class LibrariesBot(Bot):
    id, department = "libraries", DEPT

    async def run(self, ctx: BotContext) -> None:
        if no_pages_message(ctx):
            return
        urls = [a["value"] for a in db.get_assets(ctx.program_id, "js")
                if "crawler" in a["data"].get("sources", {}) or a["data"].get("pages")]
        urls += [a["value"] for a in db.get_assets(ctx.program_id, "external")
                 if a["data"].get("kind") == "script"]
        found = detect_libraries(urls, scripts(ctx))
        if not found:
            ctx.log("No recognisable library versions in script URLs or file banners.")
            return
        use_osv = bool(ctx.options.get("library_osv", True))
        vulnerable = 0
        for (name, version), where in sorted(found.items()):
            vulns = await self._osv(ctx, name, version) if use_osv else None
            ctx.asset("library", f"{name} {version}", {
                "where": {w: 1 for w in sorted(where)[:5]},
                "known_vulnerabilities": None if vulns is None else len(vulns)})
            if not vulns:
                continue
            vulnerable += 1
            worst = max((GH_SEVERITY.get(str(v.get("database_specific", {}).get("severity", "")).upper(), 0)
                         for v in vulns), default=0)
            listed = []
            for v in vulns[:12]:
                cves = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
                sev = v.get("database_specific", {}).get("severity", "")
                listed.append(f"{v.get('id')} {('(' + ', '.join(cves) + ')') if cves else ''} "
                              f"{sev}: {v.get('summary', '')[:120]}".replace("  ", " "))
            ctx.finding(
                "outdated_library", key=f"{name}|{version}",
                severity="low" if worst >= 3 else "info",
                title=f"{name} {version} has {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}",
                target=sorted(where)[0],
                detail="Version identified from the script URL or its banner. A known CVE is "
                       "only a lead: programs usually want proof that the vulnerable function "
                       "is reachable on this site (for example a jQuery selector fed with user "
                       "input).",
                evidence={"library": f"{name} {version}", "seen_in": sorted(where)[:5],
                          "vulnerabilities": listed, "source": "OSV.dev (npm advisories)"})
        ctx.flush()
        ctx.log(f"{len(found)} library versions identified; {vulnerable} with known vulnerabilities"
                + ("" if use_osv else " (vulnerability lookup turned off)"))

    async def _osv(self, ctx: BotContext, name: str, version: str) -> list[dict] | None:
        cache = ctx.shared.cache.setdefault("osv", {})
        if (name, version) not in cache:
            response = await ctx.source("https://api.osv.dev/v1/query",
                                        json_body={"version": version,
                                                   "package": {"name": name, "ecosystem": "npm"}},
                                        log_url=f"https://api.osv.dev/v1/query (npm {name} {version})")
            if response is None or response.status_code != 200:
                ctx.log(f"OSV gave no answer for {name} {version}", "warn")
                ctx.partial = True
                cache[(name, version)] = None
            else:
                cache[(name, version)] = response.json().get("vulns", [])
        return cache[(name, version)]


BOTS = {bot.id: bot for bot in (SecretsBot(), EndpointsBot(), SourceMapBot(), DebugBot(),
                                LibrariesBot())}
