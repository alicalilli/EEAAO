"""The only doors a bot has to the network.

TargetClient  - requests to the program's own hosts. GET and HEAD only, every
                URL and every redirect hop is checked by the scope guard, the
                program's rate limit is shared by all bots, required headers are
                sent, and every request is logged.
SourceClient  - requests to fixed passive data sources (crt.sh, Wayback, GitHub
                API...). Refuses any other host, so it cannot be used to reach a
                target. Never sends the program's headers. Logged.
DnsClient     - DNS lookups through the system resolver, for in-scope names only.
                Logged.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from .. import db
from ..scope import ScopeGuard

USER_AGENT = ("Mozilla/5.0 (compatible; EEAAO-passive/1.0; "
              "bug bounty research, read-only)")
MAX_BODY = 3 * 1024 * 1024
MAX_REDIRECTS = 5


class OutOfScope(Exception):
    pass


class RateLimiter:
    """Spaces requests evenly: at most `rate` per second."""

    def __init__(self, rate: float):
        self.rate = rate
        self._next = 0.0
        self._lock = asyncio.Lock()
        self._loop = None

    async def wait(self) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is not loop:
            # An asyncio.Lock belongs to one event loop. The app has a single
            # loop, but tests (and a restart inside one process) create new ones.
            self._loop, self._lock = loop, asyncio.Lock()
        async with self._lock:
            now = loop.time()
            slot = max(now, self._next)
            self._next = slot + 1.0 / self.rate
        await asyncio.sleep(max(0.0, slot - now))


_program_limiters: dict[int, RateLimiter] = {}


def program_limiter(program_id: int, rate: float) -> RateLimiter:
    """One limiter per program, shared by every bot and run of that program."""
    limiter = _program_limiters.get(program_id)
    if limiter is None or limiter.rate != rate:
        limiter = _program_limiters[program_id] = RateLimiter(rate)
    return limiter


@dataclass
class Fetched:
    url: str                     # what was asked for
    final_url: str               # after in-scope redirects
    status: int
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool
    redirects: list[str] = field(default_factory=list)
    blocked_redirect: str | None = None  # an out-of-scope Location we did not follow
    hops: list["Fetched"] = field(default_factory=list)  # redirect responses before this one

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").lower()

    def text(self) -> str:
        charset = "utf-8"
        for part in self.content_type.split(";"):
            if part.strip().startswith("charset="):
                charset = part.split("=", 1)[1].strip() or charset
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


def _is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global and not ip.is_multicast


class TargetClient:
    def __init__(self, program: dict, guard: ScopeGuard, run_id: int | None,
                 transport: httpx.AsyncBaseTransport | None = None,
                 resolve_check: bool = True):
        self.program = program
        self.guard = guard
        self.run_id = run_id
        self.limiter = program_limiter(program["id"], program["rate_limit"])
        self.resolve_check = resolve_check and transport is None
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        headers.update(program.get("headers") or {})
        self._client = httpx.AsyncClient(
            headers=headers, follow_redirects=False, timeout=httpx.Timeout(20.0),
            verify=False,  # read sites with bad certs too; the TLS department judges certs
            transport=transport)
        self._address_ok: dict[str, bool] = {}

    async def close(self) -> None:
        await self._client.aclose()

    def allowed(self, url: str) -> bool:
        return self.guard.check_automated(url).allowed

    async def _public_address(self, host: str) -> bool:
        """A hostname that resolves to a private/loopback address is refused, so
        a scope entry can never be used to reach this machine or its LAN.
        Literal IPs are taken at face value: the scope rule named them."""
        if not self.resolve_check:
            return True
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        if host not in self._address_ok:
            try:
                infos = await asyncio.get_running_loop().getaddrinfo(
                    host, None, type=socket.SOCK_STREAM)
                self._address_ok[host] = bool(infos) and all(
                    _is_public_ip(info[4][0].split("%")[0]) for info in infos)
            except OSError:
                self._address_ok[host] = True  # let the request fail normally
        return self._address_ok[host]

    async def get(self, url: str, bot: str, *, method: str = "GET",
                  follow: bool = True, max_body: int = MAX_BODY) -> Fetched | None:
        """Fetch one URL. Returns None when the request failed or was refused
        (the reason is in the request log). Raises OutOfScope for a URL the
        guard refuses, so bots notice the mistake."""
        if method not in ("GET", "HEAD"):
            raise ValueError("passive mode: only GET and HEAD")
        decision = self.guard.check_automated(url)
        if not decision.allowed:
            db.log_request(self.program["id"], self.run_id, bot, "target", method, url,
                           None, None, None, f"refused by scope guard: {decision.reason}")
            raise OutOfScope(f"{url}: {decision.reason}")

        redirects: list[str] = []
        hops: list[Fetched] = []
        current = url
        while True:
            host = urlsplit(current).hostname or ""
            if not await self._public_address(host):
                db.log_request(self.program["id"], self.run_id, bot, "target", method,
                               current, None, None, None,
                               "refused: hostname resolves to a private address")
                return None
            await self.limiter.wait()
            started = time.monotonic()
            try:
                async with self._client.stream(method, current) as response:
                    body, truncated = bytearray(), False
                    if method == "GET":
                        async for chunk in response.aiter_bytes():
                            body += chunk
                            if len(body) > max_body:
                                del body[max_body:]
                                truncated = True
                                break
                    status = response.status_code
                    headers = list(response.headers.multi_items())
                    location = response.headers.get("location")
            except (httpx.HTTPError, OSError) as exc:
                db.log_request(self.program["id"], self.run_id, bot, "target", method,
                               current, None, int((time.monotonic() - started) * 1000),
                               None, f"{type(exc).__name__}: {exc}"[:500])
                return None
            db.log_request(self.program["id"], self.run_id, bot, "target", method, current,
                           status, int((time.monotonic() - started) * 1000), len(body), None)
            fetched = Fetched(url, current, status, headers, bytes(body), truncated, redirects,
                              hops=hops)

            if not (follow and location and status in (301, 302, 303, 307, 308)):
                return fetched
            nxt = urljoin(current, location.strip())
            if len(redirects) >= MAX_REDIRECTS or nxt in redirects or nxt == current:
                return fetched
            if urlsplit(nxt).scheme not in ("http", "https") or not self.allowed(nxt):
                fetched.blocked_redirect = nxt
                return fetched
            redirects.append(current)
            # Keep the redirect response itself (headers only): sites often set
            # session cookies on a 302.
            hops.append(Fetched(current, current, status, headers, b"", False))
            current = nxt


# host -> requests per second. Kept low out of politeness to free services.
SOURCES = {
    "crt.sh": 0.5,
    "api.certspotter.com": 0.5,
    "otx.alienvault.com": 0.5,
    "web.archive.org": 0.5,
    "api.github.com": 0.15,  # code search allows ~10 requests per minute
    "api.osv.dev": 2.0,      # open vulnerability database (library CVEs)
    "data.iana.org": 0.5,    # list of domain registries' RDAP servers
    "gitlab.com": 0.5,       # public users/groups API only (Social handle bot)
}
REGISTRY_RATE = 1.0  # per RDAP server named in IANA's list
_source_limiters: dict[str, RateLimiter] = {}


class SourceClient:
    def __init__(self, program_id: int, run_id: int | None,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.program_id = program_id
        self.run_id = run_id
        self._client = httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT}, follow_redirects=False,
            timeout=httpx.Timeout(90.0), transport=transport)
        self._registries: set[str] = set()

    async def close(self) -> None:
        await self._client.aclose()

    def allow_registry(self, host: str) -> None:
        """Accept a domain registry's RDAP server for this run. Only the
        Broken link bot calls this, and only with hosts from IANA's official
        RDAP bootstrap file (data.iana.org)."""
        self._registries.add(host.lower())

    async def get(self, url: str, bot: str, *, headers: dict | None = None,
                  log_url: str | None = None, retries: int = 1,
                  json_body: dict | None = None) -> httpx.Response | None:
        """GET a source URL, or POST json_body to it (some APIs, like OSV, only
        take queries that way). Never used for targets: the host must be a
        registered source."""
        host = urlsplit(url).hostname or ""
        if urlsplit(url).scheme != "https" or (host not in SOURCES and host not in self._registries):
            raise ValueError(f"{host} is not a registered passive source")
        limiter = _source_limiters.setdefault(host, RateLimiter(SOURCES.get(host, REGISTRY_RATE)))
        for attempt in range(retries + 1):
            await limiter.wait()
            started = time.monotonic()
            try:
                if json_body is None:
                    response = await self._client.get(url, headers=headers)
                else:
                    response = await self._client.post(url, headers=headers, json=json_body)
            except (httpx.HTTPError, OSError) as exc:
                db.log_request(self.program_id, self.run_id, bot, "source",
                               "GET" if json_body is None else "POST", log_url or url, None, int((time.monotonic() - started) * 1000),
                               None, f"{type(exc).__name__}: {exc}"[:500])
                if attempt < retries:
                    await asyncio.sleep(3)
                    continue
                return None
            db.log_request(self.program_id, self.run_id, bot, "source",
                           "GET" if json_body is None else "POST", log_url or url,
                           response.status_code, int((time.monotonic() - started) * 1000),
                           len(response.content), None)
            if response.status_code in (429, 502, 503, 504) and attempt < retries:
                await asyncio.sleep(10)
                continue
            return response
        return None


@dataclass
class DnsAnswer:
    status: str  # NOERROR | NXDOMAIN | NOANSWER | SERVFAIL | TIMEOUT | ERROR | REFUSED_SCOPE
    records: list[str]
    cnames: list[str]    # CNAME chain seen while answering


class DnsClient:
    def __init__(self, program: dict, guard: ScopeGuard, run_id: int | None, resolver=None):
        self.program = program
        self.guard = guard
        self.run_id = run_id
        self.limiter = program_limiter(program["id"], program["rate_limit"])
        self._resolver = resolver
        if resolver is None:
            self._resolver = dns.asyncresolver.Resolver()
            self._resolver.lifetime = 8.0

    async def query(self, name: str, rtype: str, bot: str, *,
                    policy_for: str | None = None) -> DnsAnswer:
        """policy_for: look up a policy record that belongs to an in-scope
        domain, e.g. _dmarc.example.com for example.com. The scope check is
        made on that domain, and the name must be a '_label.' child of it."""
        owner = name
        if policy_for is not None:
            if not (name.startswith("_") and name.endswith("." + policy_for)):
                raise ValueError("policy_for only covers _underscore names under the domain")
            owner = policy_for
        if not self.guard.check_host_automated(owner).allowed:
            db.log_request(self.program["id"], self.run_id, bot, "dns", rtype, name,
                           None, None, None, "refused by scope guard")
            return DnsAnswer("REFUSED_SCOPE", [], [])
        await self.limiter.wait()
        started = time.monotonic()
        status, records, cnames = "NOERROR", [], []
        try:
            answer = await self._resolver.resolve(name, rtype, raise_on_no_answer=False)
            for rrset in answer.response.answer:
                rdtype = dns.rdatatype.to_text(rrset.rdtype)
                for item in rrset:
                    text = item.to_text()
                    if rdtype == "CNAME" and rtype != "CNAME":
                        cnames.append(text.rstrip("."))
                    elif rdtype == rtype:
                        records.append(_clean(rtype, text))
            if not records and not cnames:
                status = "NOANSWER"
        except dns.resolver.NXDOMAIN:
            status = "NXDOMAIN"
        except dns.exception.Timeout:
            status = "TIMEOUT"
        except dns.resolver.NoNameservers:
            status = "SERVFAIL"  # every nameserver failed: often a broken delegation
        except dns.exception.DNSException as exc:
            status = "ERROR"
            records = [type(exc).__name__]
        db.log_request(self.program["id"], self.run_id, bot, "dns", rtype, name, None,
                       int((time.monotonic() - started) * 1000), None,
                       None if status in ("NOERROR", "NOANSWER") else status)
        if status == "ERROR":
            records = []
        return DnsAnswer(status, records, cnames)


def _clean(rtype: str, text: str) -> str:
    if rtype == "TXT":
        # '"v=spf1 " "include:x"' -> 'v=spf1 include:x'
        parts = []
        for chunk in text.split('" "'):
            parts.append(chunk.strip('"'))
        return "".join(parts)
    return text.rstrip(".")


# ---------- TLS ----------

@dataclass
class Handshake:
    ok: bool
    version: str | None = None      # e.g. "TLSv1.3"
    cipher: str | None = None
    bits: int | None = None
    cert_der: bytes | None = None   # leaf certificate
    verified: bool | None = None    # chain + hostname check passed (verify mode only)
    verify_error: str | None = None
    error: str | None = None        # handshake failed for another reason


async def _open_tls(host: str, port: int, context: ssl.SSLContext, server_hostname: str | None):
    """Real connector: one TCP connection, one TLS handshake, then close.
    Returns (version, cipher, bits, der)."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=context, server_hostname=server_hostname,
                                ssl_handshake_timeout=10), timeout=15)
    try:
        sslobj = writer.get_extra_info("ssl_object")
        cipher = sslobj.cipher() or (None, None, None)
        return sslobj.version(), cipher[0], cipher[2], sslobj.getpeercert(binary_form=True)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=3)
        except (OSError, asyncio.TimeoutError, ssl.SSLError):
            pass


LEGACY = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1}


class TlsClient:
    """Plain TLS handshakes to in-scope HTTPS endpoints. No HTTP request is
    sent. Modes:
      verify  - what a browser does: trusted chain + hostname (one handshake)
      inspect - no verification, to read a certificate that failed verify
      legacy  - offer only one old protocol version (TLSv1 or TLSv1.1),
                to see whether the server still accepts it
    Every handshake is scope-checked, rate-limited and logged."""

    def __init__(self, program: dict, guard: ScopeGuard, run_id: int | None, connector=None):
        self.program = program
        self.guard = guard
        self.run_id = run_id
        self.limiter = program_limiter(program["id"], program["rate_limit"])
        self._connect = connector or _open_tls
        self._check_address = connector is None
        self._address_ok: dict[str, bool] = {}

    def _context(self, mode: str, legacy: str | None) -> ssl.SSLContext:
        if mode == "verify":
            return ssl.create_default_context()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        if mode == "legacy":
            import warnings
            with warnings.catch_warnings():  # TLSv1 constants are deprecated, on purpose here
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = LEGACY[legacy]
                context.maximum_version = LEGACY[legacy]
            context.set_ciphers("ALL:@SECLEVEL=0")
        return context

    async def handshake(self, url: str, bot: str, mode: str = "verify",
                        legacy: str | None = None) -> Handshake:
        decision = self.guard.check_automated(url)
        parts = urlsplit(url)
        host, port = parts.hostname or "", parts.port or 443
        label = f"TLS {mode}" + (f" {legacy}" if legacy else "")
        where = f"{host}:{port}"
        if parts.scheme != "https" or not decision.allowed:
            db.log_request(self.program["id"], self.run_id, bot, "tls", label, where,
                           None, None, None, f"refused by scope guard: {decision.reason}")
            raise OutOfScope(f"{url}: {decision.reason}")
        if self._check_address:
            if host not in self._address_ok:
                try:
                    ipaddress.ip_address(host)
                    self._address_ok[host] = True
                except ValueError:
                    try:
                        infos = await asyncio.get_running_loop().getaddrinfo(
                            host, None, type=socket.SOCK_STREAM)
                        self._address_ok[host] = bool(infos) and all(
                            _is_public_ip(i[4][0].split("%")[0]) for i in infos)
                    except OSError:
                        self._address_ok[host] = True
            if not self._address_ok[host]:
                db.log_request(self.program["id"], self.run_id, bot, "tls", label, where,
                               None, None, None, "refused: hostname resolves to a private address")
                return Handshake(False, error="refused: private address")
        try:
            ipaddress.ip_address(host)
            sni = None if mode != "verify" else host  # no SNI for IPs; verify still checks the IP
        except ValueError:
            sni = host
        await self.limiter.wait()
        started = time.monotonic()
        result: Handshake
        try:
            version, cipher, bits, der = await self._connect(host, port, self._context(mode, legacy), sni)
            result = Handshake(True, version, cipher, bits, der,
                               verified=True if mode == "verify" else None)
        except ssl.SSLCertVerificationError as exc:
            result = Handshake(False, verified=False,
                               verify_error=exc.verify_message or str(exc))
        except (ssl.SSLError, OSError, asyncio.TimeoutError, ValueError) as exc:
            result = Handshake(False, error=f"{type(exc).__name__}: {exc}"[:300])
        shown = f"{where} ({result.version}, {result.cipher})" if result.ok else where
        db.log_request(self.program["id"], self.run_id, bot, "tls", label, shown,
                       None, int((time.monotonic() - started) * 1000),
                       len(result.cert_der) if result.cert_der else None,
                       result.verify_error or result.error)
        return result
