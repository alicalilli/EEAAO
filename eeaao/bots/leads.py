"""Leads department: flag only, never test. Sends no requests.

Works from the parameters and forms in the inventory and from responses the
crawler already received. A lead is a pointer for your own manual work."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, unquote, urlsplit

from .. import db
from .base import Bot, BotContext
from .extract import endpoint
from .stored import responses

DEPT = "leads"

REDIRECT_NAMES = re.compile(
    r"^(?:url|uri|u|r|redirect|redirect_?ur[il]|redir|redirect_?to|next|next_?url|return|"
    r"return_?to|return_?ur[il]|returnurl|continue|continue_?to|dest|destination|goto|go|"
    r"target|to|out|view|link|forward|callback_?url|success_?url|fail(?:ure)?_?url|"
    r"logout_?url|login_?url|checkout_?url|image_?url|path|ref|site|domain|location)$", re.I)
URLISH_VALUE = re.compile(r"^(?:https?:|//|/|%2f|%2F|[a-z0-9.-]+\.[a-z]{2,}/)")
XSS_NAMES = re.compile(r"^(?:q|query|search|s|keyword|keywords|term|terms|message|msg|comment|"
                       r"name|title|text|content|callback|jsonp|cb|error|err|errormsg|lang|"
                       r"page_?title|description|subject|body|feedback|redirect_?msg)$", re.I)
BORING_VALUE = re.compile(r"^(?:\d+|true|false|null|on|off|yes|no|asc|desc|[a-z]{1,2})$", re.I)


def _split_param(value: str) -> tuple[str, str]:
    where, _, name = value.rpartition(" ? ")
    return where, name


class RedirectLeadsBot(Bot):
    id, department = "redirect_leads", DEPT

    async def run(self, ctx: BotContext) -> None:
        params = db.get_assets(ctx.program_id, "param")
        if not params:
            ctx.log("No parameters in the inventory. Run the Recon department first "
                    "(Crawler and Archive bots).")
            return
        flagged = 0
        for asset in params:
            where, name = _split_param(asset["value"])
            if not REDIRECT_NAMES.match(name) or not ctx.in_scope_url(where):
                continue
            example = asset["data"].get("example") or ""
            value = dict(parse_qsl(urlsplit(example).query, keep_blank_values=True)).get(name, "")
            urlish = bool(value) and bool(URLISH_VALUE.match(unquote(value)))
            if ctx.lead(
                    "lead_redirect_param", key=asset["value"], severity="low" if urlish else "info",
                    title=f"Redirect-style parameter '{name}'"
                          + (" carrying a URL" if urlish else ""),
                    target=example or where,
                    detail="Candidate for manual open-redirect testing (and, if it is used "
                           "server-side, SSRF). Nothing was tried. Check the program's stance: "
                           "many only accept open redirects that chain into something more.",
                    evidence={"endpoint": where, "parameter": name,
                              "example_value": value or None,
                              "found_by": ", ".join(asset["data"].get("sources", {})) or None,
                              "form_method": asset["data"].get("method")}):
                flagged += 1
        ctx.log(f"{flagged} new redirect-style parameters")


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
        reflected = named = forms = 0
        seen: set[str] = set()

        # 1. values the crawler sent that came back verbatim in the response
        for page in responses(ctx):
            if not page.is_html or not page.raw:
                continue
            for name, value in parse_qsl(urlsplit(page.requested).query, keep_blank_values=True):
                if len(value) < 3 or BORING_VALUE.match(value):
                    continue
                text = page.text
                at = text.find(value)
                if at < 0:
                    continue
                key = f"{endpoint(page.requested)} ? {name}"
                seen.add(key)
                context = reflection_context(text, at)
                if ctx.lead(
                        "lead_xss_param", key=key, severity="low",
                        title=f"Parameter '{name}' is reflected {context.split(' (')[0]}",
                        target=page.requested,
                        detail="The value the crawler sent came back unchanged in the page. "
                               "Reflection alone is not XSS: test manually whether special "
                               "characters survive in this context, within the program's rules.",
                        evidence={"parameter": name, "value_sent": value, "context": context,
                                  "snippet": text[max(0, at - 80):at + len(value) + 80]
                                  .replace("\n", " ")[:260]}):
                    reflected += 1

        # 2. parameters whose names suggest they are echoed back
        for asset in db.get_assets(ctx.program_id, "param"):
            where, name = _split_param(asset["value"])
            if asset["value"] in seen or not XSS_NAMES.match(name) or not ctx.in_scope_url(where):
                continue
            if ctx.lead(
                    "lead_xss_param", key=asset["value"], severity="info",
                    title=f"Parameter '{name}' is the kind often echoed back", target=where,
                    detail="Name-based guess only: no reflection was observed. Worth a look "
                           "when you test this page by hand.",
                    evidence={"endpoint": where, "parameter": name,
                              "example": asset["data"].get("example"),
                              "found_by": ", ".join(asset["data"].get("sources", {})) or None}):
                named += 1

        # 3. forms with free-text fields
        for asset in db.get_assets(ctx.program_id, "form"):
            method, _, action = asset["value"].partition(" ")
            inputs = asset["data"].get("inputs", {})
            free = [n for n, t in inputs.items()
                    if t in ("text", "search", "textarea", "url", "email", "input")]
            if not free or not ctx.in_scope_url(action):
                continue
            if ctx.lead(
                    "lead_xss_param", key=f"form|{asset['value']}", severity="info",
                    title=f"{method} form with free-text fields: {', '.join(free[:5])}",
                    target=asset["data"].get("found_on") or action,
                    detail="The bots never submit forms. Try this one yourself (search boxes, "
                           "comments, profile fields), watching where the input shows up.",
                    evidence={"action": f"{method} {action}", "free_text_fields": free,
                              "all_fields": [f"{n} ({t})" for n, t in inputs.items()]}):
                forms += 1
        ctx.log(f"{reflected} reflected values, {named} echo-prone parameter names, "
                f"{forms} forms with free-text fields")


BOTS = {bot.id: bot for bot in (RedirectLeadsBot(), XssLeadsBot())}
