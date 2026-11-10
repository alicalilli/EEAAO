"""What every bot is given, and what it must use.

A bot never builds its own HTTP client or DNS resolver: it gets them from its
BotContext, which wires in the scope guard, the rate limit, the program's
required headers and the request log. Results go out through ctx.asset(),
ctx.finding() and ctx.lead()."""
from __future__ import annotations

from dataclasses import dataclass, field

from .. import db
from ..scope import ScopeGuard
from .catalog import finding_types
from .net import DnsClient, SourceClient, TargetClient, TlsClient

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class RunShared:
    """Everything one run shares across its bots."""
    program: dict
    guard: ScopeGuard
    run_id: int | None
    target: TargetClient
    sources: SourceClient
    dns: DnsClient
    options: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    cache: dict = field(default_factory=dict)  # data bots of one run can share
    tls: TlsClient | None = None

    async def close(self) -> None:
        await self.target.close()
        await self.sources.close()


class BotContext:
    def __init__(self, shared: RunShared, department: str, bot: str):
        self.shared = shared
        self.department = department
        self.bot = bot
        self.program = shared.program
        self.program_id = shared.program["id"]
        self.guard = shared.guard
        self.options = shared.options
        self.stats = shared.counts.setdefault(bot, {"assets_new": 0, "findings_new": 0,
                                                    "leads_new": 0})
        self._pending: list[tuple[str, str, dict]] = []
        # Set by a bot when it could not do a full pass (missing input, a source
        # that did not answer). The runner then leaves its earlier cards alone.
        self.partial = False

    # --- network (all scope-checked, rate-limited, logged) ---
    async def fetch(self, url: str, **kwargs):
        return await self.shared.target.get(url, self.bot, **kwargs)

    async def source(self, url: str, **kwargs):
        return await self.shared.sources.get(url, self.bot, **kwargs)

    def allow_registry(self, host: str) -> None:
        self.shared.sources.allow_registry(host)

    async def dns(self, name: str, rtype: str, policy_for: str | None = None):
        return await self.shared.dns.query(name, rtype, self.bot, policy_for=policy_for)

    async def tls(self, url: str, mode: str = "verify", legacy: str | None = None):
        return await self.shared.tls.handshake(url, self.bot, mode, legacy)

    def in_scope_url(self, url: str) -> bool:
        return self.guard.check_automated(url).allowed

    def in_scope_host(self, host: str) -> bool:
        return self.guard.check_host_automated(host).allowed

    # --- progress ---
    def log(self, message: str, level: str = "info") -> None:
        if self.shared.run_id is not None:
            db.add_event(self.shared.run_id, self.bot, message, level)

    # --- results ---
    def asset(self, kind: str, value: str, data: dict | None = None) -> None:
        """Queue an inventory item; written in batches."""
        self._pending.append((kind, value, data or {}))
        if len(self._pending) >= 500:
            self.flush()

    def flush(self) -> None:
        if self._pending:
            self.stats["assets_new"] += db.upsert_assets(self.program_id, self._pending)
            self._pending = []

    def save_response(self, fetched) -> None:
        # Each URL keeps the response it actually returned: redirect hops under
        # their own URL (sites often set session cookies on a 302), the final
        # page under the final URL.
        for hop in fetched.hops:
            db.save_response(self.program_id, self.bot, hop.url, hop.url, hop.status,
                             hop.headers, hop.content_type, b"", False)
        key = fetched.final_url if fetched.hops else fetched.url
        db.save_response(self.program_id, self.bot, key, fetched.final_url,
                         fetched.status, fetched.headers, fetched.content_type,
                         fetched.body, fetched.truncated)

    def _report(self, kind: str, type_: str, *, title: str, target: str, key: str,
                severity: str = "info", detail: str = "", evidence: dict | None = None) -> bool:
        known = finding_types()
        if type_ not in known or known[type_]["kind"] != kind:
            raise ValueError(f"unknown {kind} type '{type_}'")
        if severity not in SEVERITIES:
            raise ValueError(f"bad severity '{severity}'")
        new = db.upsert_finding(self.program_id, {
            "kind": kind, "type": type_, "department": self.department, "bot": self.bot,
            "severity": severity, "title": title, "target": target, "detail": detail,
            "evidence": evidence or {}, "key": key})
        if new:
            self.stats["findings_new" if kind == "finding" else "leads_new"] += 1
        return new

    def finding(self, type_: str, **kwargs) -> bool:
        return self._report("finding", type_, **kwargs)

    def lead(self, type_: str, **kwargs) -> bool:
        return self._report("lead", type_, **kwargs)


class Bot:
    id: str = ""
    department: str = ""

    async def run(self, ctx: BotContext) -> None:  # pragma: no cover
        raise NotImplementedError
