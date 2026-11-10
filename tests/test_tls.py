"""TLS department with a fake TLS connector and generated certificates."""
import asyncio
import ssl
import unittest
from datetime import datetime, timedelta, timezone

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from eeaao import db
from eeaao.bots import runner
from eeaao.bots.tls import cert_info, mixed_content, name_matches
from tests.test_headers import store
from tests.test_recon import PROGRAM, DbTestCase

NOW = datetime.now(timezone.utc)
_CA_KEY = ec.generate_private_key(ec.SECP256R1())


def make_cert(names, *, self_signed=False, days=(-30, 300), rsa_bits=None) -> bytes:
    key = rsa.generate_private_key(65537, rsa_bits) if rsa_bits else ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    issuer = subject if self_signed else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org")])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(NOW + timedelta(days=days[0]))
               .not_valid_after(NOW + timedelta(days=days[1]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
                              critical=False))
    # (cryptography refuses to create SHA-1 signatures, so weak keys stand in)
    cert = builder.sign(key if self_signed else _CA_KEY, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def verify_error(message):
    exc = ssl.SSLCertVerificationError(1, message)
    exc.verify_message = message
    return exc


# host -> (verify outcome, modern handshake, cert, legacy versions accepted)
SERVERS = {
    "good.example.com": (None, ("TLSv1.3", "TLS_AES_256_GCM_SHA384"),
                         make_cert(["good.example.com"]), set()),
    "old.example.com": (None, ("TLSv1.2", "AES256-SHA"),
                        make_cert(["*.example.com"]), {"TLSv1"}),
    "expired.example.com": ("certificate has expired", ("TLSv1.3", "TLS_AES_128_GCM_SHA256"),
                            make_cert(["expired.example.com"], days=(-400, -5)), set()),
    "self.example.com": ("self-signed certificate", ("TLSv1.3", "TLS_AES_128_GCM_SHA256"),
                         make_cert(["self.example.com"], self_signed=True), set()),
    "wrong.example.com": ("Hostname mismatch, certificate is not valid for 'wrong.example.com'.",
                          ("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256"),
                          make_cert(["other.example.net"], rsa_bits=1024), set()),
}


class FakeTls:
    def __init__(self):
        self.calls = []

    async def __call__(self, host, port, context, sni):
        legacy = None
        if context.maximum_version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            legacy = "TLSv1" if context.maximum_version == ssl.TLSVersion.TLSv1 else "TLSv1.1"
        mode = "legacy" if legacy else ("verify" if context.verify_mode == ssl.CERT_REQUIRED
                                        else "inspect")
        self.calls.append((host, mode, legacy))
        if host == "admin.example.com":
            raise AssertionError("out-of-scope host contacted")
        problem, (version, cipher), der, old = SERVERS[host]
        if legacy:
            if legacy in old:
                return legacy, "ECDHE-RSA-AES128-SHA", 128, der
            raise ssl.SSLError(1, "unsupported protocol")
        if mode == "verify" and problem:
            raise verify_error(problem)
        return version, cipher, 256, der


class TlsRunTests(DbTestCase):
    def seed(self):
        pid = db.create_program(PROGRAM)
        sites = [(f"https://{h}/", {"status": 200, "final_url": f"https://{h}/"}) for h in SERVERS]
        sites += [
            ("https://admin.example.com/", {"status": 200, "final_url": "https://admin.example.com/"}),
            ("http://good.example.com/", {"status": 200, "final_url": "http://good.example.com/"}),
            ("http://plain.example.com/", {"status": 200, "final_url": "http://plain.example.com/"}),
            ("http://old.example.com/", {"status": 301, "final_url": "https://old.example.com/"}),
            # a redirect the bot could not follow is still a redirect, not content
            ("http://loop.example.com/", {"status": 301, "final_url": "http://loop.example.com/"}),
        ]
        db.upsert_assets(pid, [("site", url, data) for url, data in sites])
        store(pid, "https://good.example.com/", [
            ("Content-Type", "text/html"), ("Strict-Transport-Security", "max-age=63072000")],
            """<script src="http://cdn.example.net/a.js"></script>
               <img src='http://img.example.net/x.png'>
               <link rel="canonical" href="http://good.example.com/">
               <form action="http://good.example.com/subscribe" method=post></form>""")
        return pid

    def run_tls(self, pid, options=None):
        fake = FakeTls()

        def offline(request):
            raise AssertionError("TLS department sent an HTTP request")

        async def go():
            run_id = runner.start(db.get_program(pid), "tls", None, options or {},
                                  transport=httpx.MockTransport(offline), tls_connector=fake)
            await runner.wait(run_id)
            return run_id
        return asyncio.run(go()), fake

    def test_run(self):
        pid = self.seed()
        run_id, fake = self.run_tls(pid)
        self.assertEqual(db.get_run(run_id)["status"], "done",
                         [e["message"] for e in db.list_events(run_id)])
        self.assertFalse(any(h == "admin.example.com" for h, _, _ in fake.calls))
        # good/old: verify + 2 legacy; failing three: verify + inspect + 2 legacy
        self.assertEqual(len(fake.calls), 2 * 3 + 3 * 4)
        logged = [r for r in db.list_requests(pid, 100, 0)[1] if r["kind"] == "tls"]
        self.assertEqual(len(logged), len(fake.calls))

        findings = db.list_findings(pid, "finding")
        got = {(f["type"], f["target"]) for f in findings}
        self.assertEqual(got, {
            ("cert_expired", "https://expired.example.com/"),
            ("cert_self_signed", "https://self.example.com/"),
            ("cert_mismatch", "https://wrong.example.com/"),
            ("cert_weak", "https://wrong.example.com/"),
            ("tls_outdated", "https://old.example.com/"),
            ("tls_weak_cipher", "https://old.example.com/"),
            ("http_no_redirect", "http://good.example.com/"),
            ("http_no_redirect", "http://plain.example.com/"),
            ("mixed_content", "https://good.example.com/"),
        })
        by = {(f["type"], f["target"]): f for f in findings}
        self.assertEqual(by[("http_no_redirect", "http://good.example.com/")]["severity"], "info")
        self.assertEqual(by[("http_no_redirect", "http://plain.example.com/")]["severity"], "low")
        self.assertIn("only available over plain HTTP",
                      by[("http_no_redirect", "http://plain.example.com/")]["title"])
        weak = by[("cert_weak", "https://wrong.example.com/")]
        self.assertIn("RSA 1024", weak["detail"])
        mixed = by[("mixed_content", "https://good.example.com/")]["evidence"]
        self.assertEqual(mixed["active"], ["http://cdn.example.net/a.js"])
        self.assertEqual(mixed["passive"], ["http://img.example.net/x.png"])
        self.assertEqual(mixed["forms"], ["http://good.example.com/subscribe"])
        self.assertIn("forward secrecy", by[("tls_weak_cipher", "https://old.example.com/")]["title"])

        old = by[("tls_outdated", "https://old.example.com/")]
        self.assertEqual(old["evidence"]["total"], 1)
        self.assertIn("old.example.com:443: TLSv1", old["evidence"]["endpoints"][0])
        tls = {a["value"]: a["data"] for a in db.get_assets(pid, "tls")}
        self.assertEqual(tls["old.example.com:443"]["old_versions_accepted"], ["TLSv1"])
        self.assertTrue(tls["good.example.com:443"]["verified"])

    def test_legacy_probe_can_be_turned_off(self):
        pid = self.seed()
        _, fake = self.run_tls(pid, {"tls_legacy_probe": False})
        self.assertFalse(any(mode == "legacy" for _, mode, _ in fake.calls))
        self.assertFalse(any(f["type"] == "tls_outdated" for f in db.list_findings(pid, "finding")))


class HelperTests(unittest.TestCase):
    def test_name_matching(self):
        info = cert_info(make_cert(["*.example.com", "example.com"]))
        self.assertTrue(name_matches("www.example.com", info))
        self.assertTrue(name_matches("example.com", info))
        self.assertFalse(name_matches("a.b.example.com", info))
        self.assertFalse(name_matches("example.org", info))

    def test_mixed_content_attribute_orders(self):
        found = mixed_content('<link href="http://x/s.css" rel="stylesheet">'
                              "<LINK REL=icon HREF=http://x/f.ico>"
                              '<iframe src="https://ok/"></iframe>')
        self.assertEqual(found, {"active": ["http://x/s.css"], "passive": ["http://x/f.ico"],
                                 "form": []})


if __name__ == "__main__":
    unittest.main()
