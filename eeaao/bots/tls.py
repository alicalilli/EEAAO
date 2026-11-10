"""TLS department.

Certificate bot - one normal, browser-like handshake per HTTPS endpoint (a
                  second, non-verifying one only to read a certificate that
                  failed verification). No HTTP request is sent.
Protocol bot    - reuses that handshake; optionally two more standard
                  handshakes per endpoint, each offering only TLS 1.0 or only
                  TLS 1.1, to see whether the server still accepts them.
                  No cipher-by-cipher enumeration.
HTTPS bot       - no network at all: reads what Recon stored.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from .. import db
from .base import Bot, BotContext
from .extract import endpoint, origin
from .net import Handshake
from .stored import no_pages_message, pages

DEPT = "tls"


def https_endpoints(ctx: BotContext) -> dict[str, str]:
    """host:port -> an in-scope https URL on it, from sites Recon found live."""
    found: dict[str, str] = {}
    for site in db.get_assets(ctx.program_id, "site"):
        for url in (site["value"], site["data"].get("final_url")):
            if url and url.startswith("https://") and ctx.in_scope_url(url):
                parts = urlsplit(url)
                found.setdefault(f"{parts.hostname}:{parts.port or 443}", url)
    return found


async def first_look(ctx: BotContext, netloc: str, url: str) -> dict:
    """The browser-like handshake, shared by the department's bots.
    {'verify': Handshake, 'inspect': Handshake | None}"""
    cache = ctx.shared.cache.setdefault("tls", {})
    if netloc not in cache:
        verify = await ctx.tls(url, "verify")
        inspect = None
        if not verify.ok and verify.verified is False:
            inspect = await ctx.tls(url, "inspect")
        cache[netloc] = {"verify": verify, "inspect": inspect}
    return cache[netloc]


def best(look: dict) -> Handshake | None:
    for shake in (look["verify"], look["inspect"]):
        if shake is not None and shake.ok:
            return shake
    return None


# ---------- certificates ----------

def _names(name: x509.Name, oid) -> str:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else ""


def cert_info(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_names = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_names = [], []
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc, weak_key = f"RSA {key.key_size}", key.key_size < 2048
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc, weak_key = f"EC {key.curve.name}", key.key_size < 224
    elif isinstance(key, dsa.DSAPublicKey):
        key_desc, weak_key = f"DSA {key.key_size}", True
    else:
        key_desc, weak_key = type(key).__name__.replace("PublicKey", ""), False
    algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    return {
        "subject_cn": _names(cert.subject, x509.NameOID.COMMON_NAME),
        "issuer_cn": _names(cert.issuer, x509.NameOID.COMMON_NAME),
        "issuer_org": _names(cert.issuer, x509.NameOID.ORGANIZATION_NAME),
        "dns_names": dns_names, "ip_names": ip_names,
        "not_before": cert.not_valid_before_utc, "not_after": cert.not_valid_after_utc,
        "self_signed": cert.issuer == cert.subject,
        "signature": algo, "key": key_desc,
        "weak_signature": algo in ("md5", "sha1"), "weak_key": weak_key,
        "serial": format(cert.serial_number, "x"),
    }


def name_matches(host: str, info: dict) -> bool:
    host = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        return any(ipaddress.ip_address(i) == ip for i in info["ip_names"])
    except ValueError:
        pass
    names = info["dns_names"] or ([info["subject_cn"]] if info["subject_cn"] else [])
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host:
            # a wildcard covers exactly one label, the leftmost
            if host.split(".", 1)[1] == name[2:]:
                return True
    return False


class CertificateBot(Bot):
    id, department = "certificate", DEPT

    async def run(self, ctx: BotContext) -> None:
        endpoints = https_endpoints(ctx)
        if not endpoints:
            ctx.log("No live HTTPS sites in the inventory. Run the Recon department first.")
            return
        now = datetime.now(timezone.utc)
        problems = 0
        for netloc, url in endpoints.items():
            look = await first_look(ctx, netloc, url)
            verify, shake = look["verify"], best(look)
            if shake is None or not shake.cert_der:
                reason = verify.error or verify.verify_error or "no certificate"
                ctx.asset("tls", netloc, {"error": reason})
                ctx.log(f"{netloc}: no handshake ({reason})", "warn")
                continue
            info = cert_info(shake.cert_der)
            host = netloc.rsplit(":", 1)[0]
            is_ip = _is_ip(host)
            evidence = {
                "endpoint": netloc, "subject": info["subject_cn"] or None,
                "names": (info["dns_names"] + info["ip_names"])[:20] or None,
                "issuer": " / ".join(x for x in (info["issuer_cn"], info["issuer_org"]) if x),
                "valid": f"{info['not_before']:%Y-%m-%d} to {info['not_after']:%Y-%m-%d}",
                "key": info["key"], "signature": info["signature"],
                "browser_check": "passed" if verify.ok else (verify.verify_error or verify.error),
            }
            ctx.asset("tls", netloc, {
                "verified": verify.ok, "verify_error": verify.verify_error,
                "version": shake.version, "cipher": shake.cipher,
                "subject": info["subject_cn"], "issuer": evidence["issuer"],
                "not_after": f"{info['not_after']:%Y-%m-%d}", "names": evidence["names"]})

            def report(type_, severity, title, detail, key_extra=""):
                nonlocal problems
                problems += 1
                ctx.finding(type_, key=f"{netloc}|{info['serial']}{key_extra}", severity=severity,
                            title=title, target=url, detail=detail, evidence=evidence)

            days_left = (info["not_after"] - now).days
            if info["not_after"] < now:
                report("cert_expired", "low", f"Expired certificate on {netloc}",
                       f"The certificate expired on {info['not_after']:%Y-%m-%d}. Browsers show a "
                       "full-page warning; users who click through can be intercepted.")
            elif info["not_before"] > now:
                report("cert_expired", "low", f"Certificate on {netloc} is not valid yet",
                       f"It only becomes valid on {info['not_before']:%Y-%m-%d}.")
            elif days_left < 14:
                report("cert_expired", "info", f"Certificate on {netloc} expires in {days_left} days",
                       "Not a vulnerability yet; worth a note if it lapses.", "|soon")

            mismatch = not name_matches(host, info)
            if mismatch:
                report("cert_mismatch", "info" if is_ip else "low",
                       f"Certificate does not cover {host}",
                       f"The certificate is for {', '.join(evidence['names'] or ['(no names)'])}. "
                       "Browsers warn on every visit. Check whether this host is meant to be "
                       "public at all; a forgotten host may be the more interesting part.")
            if info["self_signed"] and not verify.ok:
                report("cert_self_signed", "low", f"Self-signed certificate on {netloc}",
                       "No trusted authority vouches for this certificate, so users get a "
                       "warning and cannot tell a real server from an impostor.")
            elif not verify.ok and not mismatch and info["not_after"] >= now:
                report("cert_untrusted", "info", f"Certificate on {netloc} is not trusted",
                       "Verification failed for another reason "
                       f"({verify.verify_error or verify.error}). Often a missing intermediate "
                       "certificate (browsers may fetch it themselves, other clients fail) or "
                       "a private CA. Check in a browser before reporting.")
            if info["weak_signature"] or info["weak_key"]:
                weak = [x for x, bad in ((f"{info['signature'].upper()} signature",
                                          info["weak_signature"]),
                                         (f"{info['key']} key", info["weak_key"])) if bad]
                report("cert_weak", "low", f"Weak certificate crypto on {netloc}",
                       f"{' and '.join(weak)}: below what browsers and the CA rules accept.")
        ctx.flush()
        ctx.log(f"Checked {len(endpoints)} HTTPS endpoints; {problems} certificate problems")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# ---------- protocol versions and ciphers ----------

WEAK_CIPHER = re.compile(r"RC4|(?<![A-Z])DES|3DES|NULL|EXP|ADH|AECDH|anon|MD5", re.I)
OLD = {"SSLv3", "TLSv1", "TLSv1.1"}


class ProtocolBot(Bot):
    id, department = "protocol", DEPT

    async def run(self, ctx: BotContext) -> None:
        endpoints = https_endpoints(ctx)
        if not endpoints:
            ctx.log("No live HTTPS sites in the inventory. Run the Recon department first.")
            return
        probe = bool(ctx.options.get("tls_legacy_probe", True))
        if not probe:
            ctx.log("Old-version checks are turned off for this run; only the normal "
                    "handshake is judged.")
        flagged = 0
        for netloc, url in endpoints.items():
            shake = best(await first_look(ctx, netloc, url))
            if shake is None:
                continue
            accepted = {}
            if shake.version in OLD:
                accepted[shake.version] = shake.cipher
            elif probe:
                for version in ("TLSv1", "TLSv1.1"):
                    legacy = await ctx.tls(url, "legacy", version)
                    if legacy.ok:
                        accepted[legacy.version or version] = legacy.cipher
            ctx.asset("tls", netloc, {"negotiated": f"{shake.version} {shake.cipher}",
                                      "old_versions_accepted": sorted(accepted) or None})
            for version, cipher in accepted.items():
                flagged += 1
                ctx.finding(
                    "tls_outdated", key=f"{netloc}|{version}",
                    severity="low", title=f"{netloc} accepts {version}", target=url,
                    detail=f"{version} is deprecated (RFC 8996) and has known weaknesses. "
                           "Programs often rate this low or exclude it; mention it mainly "
                           "for compliance-sensitive targets.",
                    evidence={"endpoint": netloc, "version": version, "cipher": cipher,
                              "normal_handshake": f"{shake.version} {shake.cipher}",
                              "how_seen": "a standard handshake that offered only this version"
                              if version != shake.version else "the server chose it for a "
                              "modern client"})
            cipher = shake.cipher or ""
            if WEAK_CIPHER.search(cipher):
                flagged += 1
                ctx.finding("tls_weak_cipher", key=f"{netloc}|{cipher}", severity="low",
                            title=f"{netloc} chose weak cipher {cipher}", target=url,
                            detail="The server picked this cipher for a modern client, so "
                                   "ordinary visitors use it.",
                            evidence={"endpoint": netloc, "negotiated": f"{shake.version} {cipher}"})
            elif shake.version != "TLSv1.3" and not cipher.startswith(("ECDHE", "DHE")):
                flagged += 1
                ctx.finding("tls_weak_cipher", key=f"{netloc}|{cipher}", severity="info",
                            title=f"{netloc} chose a cipher without forward secrecy", target=url,
                            detail=f"{cipher} uses RSA key exchange: anyone who later obtains "
                                   "the server key can decrypt recorded traffic.",
                            evidence={"endpoint": netloc, "negotiated": f"{shake.version} {cipher}"})
        ctx.flush()
        ctx.log(f"Checked {len(endpoints)} HTTPS endpoints; {flagged} protocol/cipher results")


# ---------- HTTP to HTTPS, mixed content ----------

_TAG = re.compile(r"<(script|iframe|frame|link|img|audio|video|source|object|embed|form)\b([^>]*)>",
                  re.I)
_ATTR = re.compile(r"""([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_SRC = {"script": "src", "iframe": "src", "frame": "src", "img": "src", "audio": "src",
        "video": "src", "source": "src", "embed": "src", "object": "data", "form": "action",
        "link": "href"}
_ACTIVE = {"script", "iframe", "frame", "object", "embed"}


def mixed_content(html: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {"active": [], "passive": [], "form": []}
    for match in _TAG.finditer(html[:500_000]):
        tag = match.group(1).lower()
        attrs = {m.group(1).lower(): (m.group(2) or m.group(3) or m.group(4) or "")
                 for m in _ATTR.finditer(match.group(2))}
        url = attrs.get(_SRC[tag], "").strip()
        if not url.lower().startswith("http://"):
            continue
        if tag == "link":
            rel = attrs.get("rel", "").lower()
            if any(r in rel for r in ("stylesheet", "preload", "modulepreload")):
                kind = "active"
            elif "icon" in rel:
                kind = "passive"
            else:
                continue  # canonical/alternate links are not loaded
        elif tag == "form":
            kind = "form"
        else:
            kind = "active" if tag in _ACTIVE else "passive"
        if url not in found[kind] and len(found[kind]) < 20:
            found[kind].append(url)
    return found


class HttpsBot(Bot):
    id, department = "https", DEPT

    async def run(self, ctx: BotContext) -> None:
        sites = db.get_assets(ctx.program_id, "site")
        if not sites:
            ctx.log("No live sites in the inventory. Run the Recon department first.")
            return
        https_hosts = {k.rsplit(":", 1)[0] for k in https_endpoints(ctx)}
        flagged = 0
        for site in sites:
            url, data = site["value"], site["data"]
            if not url.startswith("http://") or not ctx.in_scope_url(url):
                continue
            final = data.get("final_url") or url
            upgraded = final.startswith("https://") or (data.get("blocked_redirect") or "").startswith("https://")
            if upgraded or not data.get("status") or data["status"] >= 400:
                continue
            host = urlsplit(url).hostname
            flagged += 1
            has_https = host in https_hosts
            hsts = None
            if has_https:
                for page in pages(ctx):
                    if urlsplit(page.url).hostname == host and page.https:
                        hsts = page.header("strict-transport-security")
                        if hsts:
                            break
            ctx.finding(
                "http_no_redirect", key=origin(url), severity="info" if hsts else "low",
                title=(f"{origin(url)} serves content over HTTP instead of redirecting to HTTPS"
                       if has_https else f"{host} is only available over plain HTTP"),
                target=url,
                detail=("HTTPS works on this host, but the http:// address answers with "
                        f"status {data['status']} instead of redirecting, so a first visit "
                        "can be intercepted. " + ("HSTS on the HTTPS site protects returning "
                                                   "visitors." if hsts else "No HSTS was seen "
                                                   "either."))
                       if has_https else
                       "No working HTTPS was found for this host, so everything, including "
                       "any login or cookies, travels unencrypted.",
                evidence={"http_response": f"{data['status']} at {final}",
                          "https_available": has_https, "hsts": hsts or "(none seen)"})

        if no_pages_message(ctx):
            ctx.flush()
            return
        mixed_pages = 0
        for page in pages(ctx):
            if not (page.https and page.is_html):
                continue
            found = mixed_content(page.text)
            if not any(found.values()):
                continue
            mixed_pages += 1
            severity = "low" if found["active"] or found["form"] else "info"
            what = [label for label, key in (("scripts/frames/styles", "active"),
                                             ("forms posting over HTTP", "form"),
                                             ("images/media", "passive")) if found[key]]
            ctx.finding(
                "mixed_content", key=endpoint(page.url), severity=severity,
                title=f"HTTPS page loads {' and '.join(what)} over HTTP", target=page.url,
                detail="Modern browsers block active mixed content (and the page breaks) and "
                       "warn on the rest; older clients load it, letting a network attacker "
                       "swap it. A form that posts to http:// sends its data unencrypted.",
                evidence={"active": found["active"] or None, "forms": found["form"] or None,
                          "passive": found["passive"] or None, "fetched_at": page.fetched_at})
        ctx.flush()
        ctx.log(f"{flagged} hosts without HTTP-to-HTTPS redirect; {mixed_pages} pages with "
                "mixed content")


BOTS = {bot.id: bot for bot in (CertificateBot(), ProtocolBot(), HttpsBot())}
