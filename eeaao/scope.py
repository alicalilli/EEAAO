"""Scope guard: the single gate every target must pass before anything touches it.

Principles
----------
* Default deny: a target is allowed only if an in-scope rule matches it.
* Out-of-scope always wins over in-scope.
* Fail closed: a target that cannot be parsed, or a guard holding a rule that
  could not be parsed, allows nothing.
* Strict when allowing, conservative when denying: if an in-scope rule is
  limited to a scheme, port or path, the target must state a matching one;
  an out-of-scope rule blocks a target whenever it *might* apply.

Supported rule syntax (one per line)
------------------------------------
    example.com                 exact host, any scheme and port
    *.example.com               any subdomain depth (NOT the bare example.com)
    api-*.example.com           wildcard inside one label
    https://example.com         that scheme and its default port only
    example.com:8443            that port only
    https://example.com/api/    that path and everything under it
    203.0.113.0/24, 203.0.113.7 IP networks and addresses

The guard works on names and URLs. It does not resolve DNS, so it cannot tell
whether an in-scope hostname points at third-party infrastructure.
"""
from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


class ScopeError(ValueError):
    """A scope rule or target that cannot be understood safely."""


_DEFAULT_PORTS = {"http": 80, "https": 443}
_BAD_CHARS = re.compile(r"[\s\\\x00-\x1f\x7f]")
_LABEL = re.compile(r"^[a-z0-9_*]([a-z0-9_*-]*[a-z0-9_*])?$")
_LABEL_CHARS = "[a-z0-9_-]"
# Two-label public suffixes under which a wildcard would cover unrelated
# organisations. Not exhaustive; it catches the common mistakes.
_BROAD_SUFFIXES = frozenset(
    f"{second}.{tld}"
    for tld in ("uk", "au", "nz", "jp", "br", "in", "za", "tr", "mx", "kr",
                "cn", "tw", "hk", "sg", "il", "ar", "az", "ru", "ua")
    for second in ("co", "com", "net", "org", "gov", "edu", "ac", "or", "ne")
)


def _split(raw: str) -> tuple[str | None, str, int | None, str]:
    """Split a rule or target into (scheme, host, explicit port, path)."""
    text = raw.strip()
    if not text:
        raise ScopeError("empty")
    if _BAD_CHARS.search(text):
        raise ScopeError("contains whitespace, a backslash or a control character")
    parts = urlsplit(text if "://" in text else "//" + text)
    scheme = parts.scheme.lower() or None
    if scheme is not None and scheme not in _DEFAULT_PORTS:
        raise ScopeError(f"unsupported scheme '{scheme}' (only http and https)")
    if "@" in parts.netloc:
        raise ScopeError("user info ('@') is not allowed in a host")
    try:
        host, port = parts.hostname, parts.port
    except ValueError as exc:
        raise ScopeError(f"bad host or port: {exc}") from None
    if not host:
        raise ScopeError("no host")
    if port is not None and not 0 < port < 65536:
        raise ScopeError("port out of range")
    return scheme, _norm_host(host), port, _norm_path(parts.path)


def _norm_host(host: str) -> str:
    host = host.strip().rstrip(".").lower()
    if not host:
        raise ScopeError("no host")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise ScopeError("host is not a valid internationalised name") from None
    return host


def _norm_path(path: str) -> str:
    """Decode and collapse a path so '/api/../admin' cannot pose as '/api/'."""
    if not path:
        return "/"
    for _ in range(3):  # undo nested percent-encoding
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if _BAD_CHARS.search(path):
        raise ScopeError("path contains whitespace, a backslash or a control character")
    trailing = path.endswith("/")
    path = posixpath.normpath("/" + path.lstrip("/"))
    if trailing and path != "/":
        path += "/"
    return path


def _path_under(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    stem = prefix.rstrip("/")
    return path == stem or path.startswith(stem + "/")


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


@dataclass(frozen=True)
class Target:
    raw: str
    scheme: str | None
    host: str
    port: int | None
    path: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None

    @classmethod
    def parse(cls, raw: str) -> "Target":
        scheme, host, port, path = _split(raw)
        if "*" in host:
            raise ScopeError("a target cannot contain a wildcard")
        if port is None and scheme is not None:
            port = _DEFAULT_PORTS[scheme]
        return cls(raw.strip(), scheme, host, port, path, _as_ip(host))


@dataclass(frozen=True)
class Rule:
    raw: str
    kind: str  # "exact" | "wildcard" | "network"
    scheme: str | None
    host: str | None
    pattern: re.Pattern | None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None
    port: int | None
    path: str

    @classmethod
    def parse(cls, raw: str) -> "Rule":
        text = raw.strip()
        if "://" not in text:
            try:  # bare address or CIDR block such as 203.0.113.0/24
                net = ipaddress.ip_network(text, strict=False)
                return cls(text, "network", None, None, None, net, None, "/")
            except ValueError:
                pass
        scheme, host, port, path = _split(text)
        if port is None and scheme is not None:
            port = _DEFAULT_PORTS[scheme]
        ip = _as_ip(host)
        if ip is not None:
            net = ipaddress.ip_network(ip)
            return cls(text, "network", scheme, None, None, net, port, path)
        labels = host.split(".")
        if not all(_LABEL.match(label) for label in labels):
            raise ScopeError("host contains characters that are not valid in a hostname")
        if "*" not in host:
            return cls(text, "exact", scheme, host, None, None, port, path)
        # Wildcards may not reach into the registrable domain (example.com).
        keep = 3 if ".".join(labels[-2:]) in _BROAD_SUFFIXES else 2
        if len(labels) <= keep or any("*" in label for label in labels[-keep:]):
            raise ScopeError(
                "wildcard is too broad: it must sit left of a full domain, "
                "like *.example.com"
            )
        pieces = []
        for index, label in enumerate(labels):
            if label == "*":
                # A leading '*' spans any number of subdomain levels.
                pieces.append(f"(?:{_LABEL_CHARS}+\\.)+" if index == 0
                              else f"{_LABEL_CHARS}+\\.")
            else:
                pieces.append(re.escape(label).replace(r"\*", f"{_LABEL_CHARS}*") + r"\.")
        pattern = re.compile("".join(pieces)[:-2])  # drop the final '\.'
        return cls(text, "wildcard", scheme, host, pattern, None, port, path)

    def host_matches(self, target: Target) -> bool:
        if self.kind == "network":
            ip = target.ip
            return (ip is not None and ip.version == self.network.version
                    and ip in self.network)
        if target.ip is not None:
            return False
        if self.kind == "exact":
            return target.host == self.host
        return bool(self.pattern.fullmatch(target.host))

    def matches(self, target: Target, *, conservative: bool) -> bool:
        """conservative=True (used for out-of-scope rules) treats anything the
        target leaves unstated - scheme, port - as matching."""
        if not self.host_matches(target):
            return False

        if self.scheme is not None:
            if target.scheme is None:
                if not conservative:
                    return False
            elif target.scheme != self.scheme:
                return False
        if self.port is not None:
            if target.port is None:
                if not conservative:
                    return False
            elif target.port != self.port:
                return False
        if conservative:
            return _path_under(target.path.lower(), self.path.lower())
        return _path_under(target.path, self.path)

    def describe(self) -> dict:
        return {"raw": self.raw, "kind": self.kind}


@dataclass(frozen=True)
class Decision:
    target: str
    allowed: bool
    reason: str
    rule: str | None = None

    def as_dict(self) -> dict:
        return {"target": self.target, "allowed": self.allowed,
                "reason": self.reason, "rule": self.rule}


def parse_scope_text(text: str) -> list[str]:
    """Turn a pasted scope list into entries: one per line or comma, with
    '# comments' and '- ' / '• ' bullets removed."""
    entries = []
    for line in re.split(r"[\r\n,]+", text or ""):
        line = line.split("#", 1)[0].strip()
        line = re.sub(r"^(?:[-•]\s+)", "", line).strip()
        if line:
            entries.append(line)
    return entries


class ScopeGuard:
    def __init__(self, in_scope, out_of_scope, automation_allowed: bool = False):
        self.automation_allowed = bool(automation_allowed)
        self.errors: list[dict] = []
        self.allow = self._load(in_scope, "in_scope")
        self.deny = self._load(out_of_scope, "out_of_scope")

    def _load(self, entries, source: str) -> list[Rule]:
        if isinstance(entries, str):
            entries = parse_scope_text(entries)
        rules, seen = [], set()
        for raw in entries:
            try:
                rule = Rule.parse(raw)
            except ScopeError as exc:
                self.errors.append({"list": source, "entry": raw, "error": str(exc)})
                continue
            if rule.raw.lower() not in seen:
                seen.add(rule.raw.lower())
                rules.append(rule)
        return rules

    def check(self, raw_target: str) -> Decision:
        """Is this target in scope? Says nothing about automation."""
        shown = str(raw_target).strip()
        if self.errors:
            return Decision(shown, False,
                            "Scope list has entries that could not be read; "
                            "nothing is allowed until they are fixed.")
        try:
            target = Target.parse(shown)
        except ScopeError as exc:
            return Decision(shown, False, f"Not a usable target: {exc}.")
        for rule in self.deny:
            if rule.matches(target, conservative=True):
                return Decision(shown, False, "Explicitly out of scope.", rule.raw)
        for rule in self.allow:
            if rule.matches(target, conservative=False):
                return Decision(shown, True, "In scope.", rule.raw)
        for rule in self.allow:
            if rule.host_matches(target):
                return Decision(shown, False,
                                "Only part of this host is in scope (the rule is "
                                "limited by scheme, port or path).", rule.raw)
        return Decision(shown, False, "No in-scope rule matches (default deny).")

    def check_automated(self, raw_target: str) -> Decision:
        """The gate automated tools must use: scope AND the automation switch."""
        if not self.automation_allowed:
            return Decision(str(raw_target).strip(), False,
                            "Automated scanning is turned off for this program.")
        return self.check(raw_target)

    def check_host_automated(self, host: str) -> Decision:
        """For name-level work that never contacts the host's web server (DNS
        lookups, keeping a hostname in the inventory). Allowed when automation
        is on, some in-scope rule covers the host, and no out-of-scope rule
        covers the whole host. Every HTTP request still goes through
        check_automated with its full URL."""
        shown = str(host).strip()
        if not self.automation_allowed:
            return Decision(shown, False, "Automated scanning is turned off for this program.")
        if self.errors:
            return Decision(shown, False, "Scope list has entries that could not be read.")
        try:
            target = Target.parse(shown)
        except ScopeError as exc:
            return Decision(shown, False, f"Not a usable host: {exc}.")
        if target.path != "/" or target.scheme or target.port:
            return Decision(shown, False, "Not a bare host name.")
        for rule in self.deny:
            if rule.matches(target, conservative=True):
                return Decision(shown, False, "Explicitly out of scope.", rule.raw)
        for rule in self.allow:
            if rule.host_matches(target):
                return Decision(shown, True, "Host is (at least partly) in scope.", rule.raw)
        return Decision(shown, False, "No in-scope rule matches (default deny).")

    def seed_hosts(self) -> list[str]:
        """Exact host names and single IP addresses named by in-scope rules."""
        seeds = []
        for rule in self.allow:
            if rule.kind == "exact":
                seeds.append(rule.host)
            elif rule.kind == "network" and rule.network.num_addresses == 1:
                seeds.append(str(rule.network.network_address))
        return list(dict.fromkeys(seeds))

    def seed_domains(self) -> list[str]:
        """Parent domains of wildcard rules ('*.example.com' -> 'example.com'),
        the names to ask passive sources about."""
        domains = []
        for rule in self.allow:
            if rule.kind == "wildcard":
                labels = rule.host.split(".")
                while labels and "*" in labels[0]:
                    labels.pop(0)
                if len(labels) >= 2:
                    domains.append(".".join(labels))
        return list(dict.fromkeys(domains))

    def filter_automated(self, targets) -> tuple[list[str], list[Decision]]:
        """Split targets into (allowed targets, refused decisions)."""
        allowed, refused = [], []
        for target in targets:
            decision = self.check_automated(target)
            (allowed.append(decision.target) if decision.allowed
             else refused.append(decision))
        return allowed, refused
