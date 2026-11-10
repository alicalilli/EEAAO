"""Read-only access to the responses Recon already downloaded.

Departments that only analyse (Headers, Cookies, Content...) use this instead
of asking the target again: zero extra load on the program's servers."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from urllib.parse import urlsplit

from .. import db
from .base import BotContext
from .extract import origin, parse_html

MAX_TEXT = 500_000


@dataclass
class Page:
    url: str          # final URL (after in-scope redirects)
    requested: str
    status: int
    headers: list[tuple[str, str]]
    content_type: str
    raw: bytes
    fetched_at: str
    _cache: dict = field(default_factory=dict, repr=False)

    def header(self, name: str) -> str | None:
        """All values of a header joined with ', ' (as HTTP allows), or None."""
        values = self.header_all(name)
        return ", ".join(values) if values else None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def origin(self) -> str:
        return origin(self.url)

    @property
    def https(self) -> bool:
        return self.url.startswith("https://")

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type

    @cached_property
    def text(self) -> str:
        return self.raw[:MAX_TEXT].decode("utf-8", errors="replace")

    @cached_property
    def html(self) -> dict:
        empty = {"title": "", "generator": "", "links": [], "scripts": [], "forms": [],
                 "meta_csp": [], "meta_referrer": ""}
        return parse_html(self.text, self.url) if self.is_html else empty

    def snapshot(self, *names: str) -> dict:
        """Header values for evidence; '(absent)' when missing."""
        return {n: self.header(n) or "(absent)" for n in names}


def pages(ctx: BotContext) -> list[Page]:
    """Successful (2xx) stored responses, one per final URL, still in scope.
    Loaded once per run and shared by the department's bots."""
    cache = ctx.shared.cache
    if "pages" not in cache:
        found, seen = [], set()
        for row in db.iter_responses(ctx.program_id):
            final = row["final_url"]
            if not 200 <= row["status"] < 300 or final in seen:
                continue
            if not ctx.in_scope_url(final):
                continue
            seen.add(final)
            found.append(Page(url=final, requested=row["url"], status=row["status"],
                              headers=[tuple(h) for h in row["headers"]],
                              content_type=(row["content_type"] or "").lower(),
                              raw=bytes(row["body"] or b""), fetched_at=row["fetched_at"]))
        cache["pages"] = found
    return cache["pages"]


def responses(ctx: BotContext) -> list[Page]:
    """Every stored response of any status, including redirect hops, still in
    scope. Page.url is the URL whose response the headers belong to."""
    cache = ctx.shared.cache
    if "responses" not in cache:
        found = []
        for row in db.iter_responses(ctx.program_id):
            final = row["final_url"]
            if ctx.in_scope_url(final):
                found.append(Page(url=final, requested=row["url"], status=row["status"],
                                  headers=[tuple(h) for h in row["headers"]],
                                  content_type=(row["content_type"] or "").lower(),
                                  raw=bytes(row["body"] or b""), fetched_at=row["fetched_at"]))
        cache["responses"] = found
    return cache["responses"]


def by_origin(items: list[Page]) -> dict[str, list[Page]]:
    groups: dict[str, list[Page]] = {}
    for page in items:
        groups.setdefault(page.origin, []).append(page)
    return groups


def no_pages_message(ctx: BotContext) -> bool:
    """Log and return True when there is nothing to analyse."""
    if not pages(ctx):
        ctx.log("No stored responses yet. Run the Recon department first "
                "(Live host, Public files and Crawler bots store what they fetch).")
        return True
    return False
