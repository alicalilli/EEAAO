"""Leads department: flag only, never test. Sends no requests.

Works from the parameters and forms in the inventory and from responses the
crawler already received. A lead is a pointer for your own manual work.

Leads are grouped so one idea is one card: the same search box on forty pages,
or the same parameter name all over a site, is a single lead that lists
examples. Static files (scripts, images, fonts) and image-resizer endpoints are
left out, because their parameters select a file or a size, not page content."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .. import db
from .base import Bot, BotContext
from .extract import endpoint
from .stored import responses

DEPT = "leads"

# Names that usually carry a destination.
REDIRECT_NAMES = re.compile(
    r"^(?:url|uri|redirect|redirect_?ur[il]|redir|redirect_?to|next|next_?url|return|"
    r"return_?to|return_?ur[il]|returnurl|continue|continue_?to|dest|destination|goto|"
    r"target|forward|callback_?url|success_?url|fail(?:ure)?_?url|logout_?url|login_?url|"
    r"checkout_?url|image_?url|redirect_?uri)$", re.I)
# Short or ambiguous names: only interesting when the value really is a URL or path.
REDIRECT_MAYBE = re.compile(r"^(?:u|r|to|go|out|link|ref|view|path|site|domain|location|page)$", re.I)
ABSOLUTE_URL = re.compile(r"^(?:https?:)?//[a-z0-9.-]+\.[a-z]{2,}", re.I)
PATH_VALUE = re.compile(r"^/[^/\s]")
XSS_NAMES = re.compile(r"^(?:q|query|search|s|keyword|keywords|term|terms|message|msg|comment|"
                       r"name|title|text|content|callback|jsonp|cb|error|err|errormsg|"
                       r"page_?title|description|subject|body|feedback|redirect_?msg)$", re.I)
BORING_VALUE = re.compile(r"^(?:\d+|true|false|null|on|off|yes|no|asc|desc|[a-z]{1,2})$", re.I)
STATIC_FILE = re.compile(r"\.(?:js|mjs|css|map|png|jpe?g|gif|svg|webp|avif|ico|bmp|woff2?|ttf|"
                         r"otf|eot|mp[34]|webm|ogg|wav|pdf|zip|gz|xml|txt|swf)$", re.I)
IMAGE_RESIZER = re.compile(r"/_next/image$|/_ipx/|/cdn-cgi/image/|/_vercel/image$|/imgproxy/", re.I)


def _split_param(value: str) -> tuple[str, str]:
    where, _, name = value.rpartition(" ? ")
    return where, name


def _host(url: str) -> str:
    return urlsplit(url).netloc.lower()


def _is_static(where: str) -> bool:
    return bool(STATIC_FILE.search(urlsplit(where).path))


def _is_resizer(where: str) -> bool:
    return bool(IMAGE_RESIZER.search(urlsplit(where).path))


def _example_value(asset: dict, name: str) -> str:
    example = asset["data"].get("example") or ""
    return dict(parse_qsl(urlsplit(example).query, keep_blank_values=True)).get(name, "")


class RedirectLeadsBot(Bot):
    id, department = "redirect_leads", DEPT

    async def run(self, ctx: BotContext) -> None:
        params = db.get_assets(ctx.program_id, "param")
        if not params:
            ctx.log("No parameters in the inventory. Run the Recon department first "
                    "(Crawler and Archive bots).")
            ctx.partial = True  # input missing: keep earlier cards
            return
        # (host, parameter) -> best observation + all endpoints
        groups: dict[tuple[str, str], dict] = {}
        skipped_static = 0
        for asset in params:
            where, name = _split_param(asset["value"])
            if not ctx.in_scope_url(where):
                continue
            value = unquote(_example_value(asset, name))
            absolute = bool(ABSOLUTE_URL.match(value))
            pathlike = bool(PATH_VALUE.match(value))
            named = bool(REDIRECT_NAMES.match(name))
            maybe = bool(REDIRECT_MAYBE.match(name))
            resizer = _is_resizer(where)
            if resizer and named:
                rank, why = 2, "an image-resizer endpoint that fetches whatever this points to"
            elif _is_static(where) or resizer:
                skipped_static += named or absolute
                continue
            elif absolute and (named or maybe):
                rank, why = 3, "a redirect-style name carrying a full URL"
            elif absolute:
                rank, why = 2, "its value is a full URL, whatever the name"
            elif named and pathlike:
                rank, why = 2, "a redirect-style name carrying a path"
            elif named:
                rank, why = 1, "a redirect-style name (no URL value seen)"
            else:
                continue
            group = groups.setdefault((_host(where), name.lower()),
                                      {"rank": 0, "endpoints": [], "sources": set()})
            if where not in group["endpoints"]:
                group["endpoints"].append(where)
            group["sources"].update(asset["data"].get("sources", {}))
            if rank > group["rank"]:
                group.update(rank=rank, why=why, name=name, value=value,
                             example=asset["data"].get("example") or where,
                             resizer=resizer)
        flagged = 0
        for (host, _), g in groups.items():
            count = len(g["endpoints"])
            if ctx.lead(
                    "lead_redirect_param", key=f"{host}|{g['name'].lower()}",
                    severity="low" if g["rank"] >= 2 else "info",
                    title=(f"Image resizer takes a '{g['name']}' parameter on {host}" if g["resizer"]
                           else f"Parameter '{g['name']}' on {host}: {g['why']}"),
                    target=g["example"],
                    detail=("The endpoint downloads the image this parameter names. Check by "
                            "hand whether it accepts hosts other than the site's own (a "
                            "server-side request to a host you choose), within program rules. "
                            if g["resizer"] else
                            "Candidate for manual open-redirect testing (and SSRF, if the "
                            "server fetches it). Nothing was tried. ") +
                           "Check the program's stance: some only accept open redirects that "
                           "chain into something more.",
                    evidence={"parameter": g["name"], "why_flagged": g["why"],
                              "example_value": g["value"] or None,
                              "seen_on": f"{count} endpoint{'s' if count != 1 else ''}",
                              "endpoints": g["endpoints"][:8],
                              "found_by": ", ".join(sorted(g["sources"])) or None}):
                flagged += 1
        ctx.log(f"{len(groups)} redirect-style parameters ({flagged} new)"
                + (f"; {skipped_static} on static files skipped" if skipped_static else ""))


def reflection_context(text: str, at: int) -> str:
    before = text[max(0, at - 2000):at].lower()
    if before.rfind("<script") > before.rfind("</script"):
        return "inside a <script> block"
    if before.rfind("<!--") > before.rfind("-->"):
        return "inside an HTML comment"
    tag_open, tag_close = before.rfind("<"), before.rfind(">")
    if tag_open > tag_close:
        return "inside an HTML tag (attribute)"
    if before.rfind("<textarea") > before.rfind("</textarea") or \
            before.rfind("<title") > before.rfind("</title"):
        return "inside <textarea>/<title> (RCDATA)"
    return "in HTML text"


class XssLeadsBot(Bot):
    id, department = "xss_leads", DEPT

    async def run(self, ctx: BotContext) -> None:
        reflected = 0
        reflected_keys: set[tuple[str, str]] = set()

        # 1. values the crawler sent that came back verbatim in the response
        for page in responses(ctx):
            if not page.is_html or not page.raw or _is_resizer(page.requested):
                continue
            for name, value in parse_qsl(urlsplit(page.requested).query, keep_blank_values=True):
                if len(value) < 3 or BORING_VALUE.match(value):
                    continue
                text = page.text
                at = text.find(value)
                if at < 0:
                    continue
                where = endpoint(page.requested)
                reflected_keys.add((_host(where), name.lower()))
                context = reflection_context(text, at)
                if ctx.lead(
                        "lead_xss_param", key=f"{where} ? {name}", severity="low",
                        title=f"Parameter '{name}' is reflected {context.split(' (')[0]}",
                        target=page.requested,
                        detail="The value the crawler sent came back unchanged in the page. "
                               "Reflection alone is not XSS: test manually whether special "
                               "characters survive in this context, within the program's rules.",
                        evidence={"parameter": name, "value_sent": value, "context": context,
                                  "snippet": text[max(0, at - 80):at + len(value) + 80]
                                  .replace("\n", " ")[:260]}):
                    reflected += 1

        # 2. forms with free-text fields: one lead per distinct form on a site
        forms: dict[tuple[str, str, tuple[str, ...]], dict] = {}
        form_fields: set[tuple[str, str]] = set()
        for asset in db.get_assets(ctx.program_id, "form"):
            method, _, action = asset["value"].partition(" ")
            inputs = asset["data"].get("inputs", {})
            free = tuple(sorted(n for n, t in inputs.items()
                                if t in ("text", "search", "textarea", "url", "email", "input")))
            if not free or not ctx.in_scope_url(action):
                continue
            host = _host(action)
            group = forms.setdefault((host, method, free), {"pages": [], "inputs": inputs,
                                                           "action": action})
            page = asset["data"].get("found_on") or action
            if page not in group["pages"]:
                group["pages"].append(page)
            form_fields.update((host, n.lower()) for n in free)
        new_forms = 0
        for (host, method, free), g in forms.items():
            count = len(g["pages"])
            if ctx.lead(
                    "lead_xss_param", key=f"form|{host}|{method}|{','.join(free)}", severity="info",
                    title=f"{method} form with free-text field{'s' if len(free) != 1 else ''} "
                          f"{', '.join(free[:5])} on {host}",
                    target=g["pages"][0],
                    detail="The bots never submit forms. Try this one yourself (search boxes, "
                           "comments, profile fields), watching where the input shows up. "
                           + (f"The same form appears on {count} pages; it is one lead."
                              if count > 1 else ""),
                    evidence={"example_action": f"{method} {g['action']}",
                              "free_text_fields": list(free),
                              "all_fields": [f"{n} ({t})" for n, t in g["inputs"].items()],
                              "seen_on": f"{count} page{'s' if count != 1 else ''}",
                              "pages": g["pages"][:8]}):
                new_forms += 1

        # 3. parameter names that are often echoed back: one lead per name per site
        named: dict[tuple[str, str], dict] = {}
        for asset in db.get_assets(ctx.program_id, "param"):
            where, name = _split_param(asset["value"])
            key = (_host(where), name.lower())
            if not XSS_NAMES.match(name) or not ctx.in_scope_url(where):
                continue
            if _is_static(where) or _is_resizer(where):
                continue  # ?q=75 on an image is quality, not a query
            if key in reflected_keys or key in form_fields:
                continue  # already covered by a stronger or equivalent lead
            group = named.setdefault(key, {"name": name, "endpoints": [], "sources": set(),
                                           "example": None})
            if where not in group["endpoints"]:
                group["endpoints"].append(where)
            group["sources"].update(asset["data"].get("sources", {}))
            group["example"] = group["example"] or asset["data"].get("example")
        new_named = 0
        for (host, _), g in named.items():
            count = len(g["endpoints"])
            if ctx.lead(
                    "lead_xss_param", key=f"name|{host}|{g['name'].lower()}", severity="info",
                    title=f"Parameter '{g['name']}' on {host} is the kind often echoed back",
                    target=g["example"] or g["endpoints"][0],
                    detail="Name-based guess only: no reflection was observed. Worth a look "
                           "when you test these pages by hand.",
                    evidence={"parameter": g["name"],
                              "seen_on": f"{count} endpoint{'s' if count != 1 else ''}",
                              "endpoints": g["endpoints"][:8],
                              "example": (g["example"] or "")[:300] or None,
                              "found_by": ", ".join(sorted(g["sources"])) or None}):
                new_named += 1
        ctx.log(f"{reflected} new reflected values; {len(forms)} distinct free-text forms "
                f"({new_forms} new); {len(named)} echo-prone parameter names ({new_named} new)")


BOTS = {bot.id: bot for bot in (RedirectLeadsBot(), XssLeadsBot())}
