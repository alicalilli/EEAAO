"""Local fixture website for manual end-to-end runs (127.0.0.1 only).

Serves tests/fixtures/site and adds a few cookies, plus /go-login, a redirect
that sets a session cookie on the 302 (like many real login flows).
The same site is also served over HTTPS on port - 1 with a poor TLS setup.
Run: .venv/Scripts/python.exe tests/fixtures/serve.py [port]
"""
import ssl
import sys
import tempfile
import threading
import warnings
from datetime import datetime, timedelta, timezone
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SITE = Path(__file__).resolve().parent / "site"


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/go-login"):
            self.send_response(302)
            self.send_header("Location", "/docs/index.html")
            self.send_header("Set-Cookie", "auth_session=Zx9qT2mLp8Vb4Rk7Wc1Nf6Hy3Jd5Gs0A; Path=/")
            self.end_headers()
            return
        super().do_GET()

    def end_headers(self):
        if self.path in ("/", "/index.html"):
            self.send_header("Set-Cookie", "sessionid=abc123def456ghi789; Path=/")
            self.send_header("Set-Cookie", "csrftoken=k3j4h5g6f7d8; Path=/; SameSite=Strict")
            self.send_header("Set-Cookie", "theme=dark; Path=/")
        super().end_headers()


def tls_context() -> ssl.SSLContext:
    """A deliberately poor HTTPS setup: self-signed certificate for the wrong
    name (fixture.test), and TLS 1.0 still accepted."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.test")]), False)
            .sign(key, hashes.SHA256()))
    folder = Path(tempfile.mkdtemp(prefix="eeaao-fixture-"))
    (folder / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = ssl.TLSVersion.TLSv1
    context.set_ciphers("ALL:@SECLEVEL=0")
    context.load_cert_chain(folder / "cert.pem", folder / "key.pem")
    return context


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    handler = partial(Handler, directory=str(SITE))
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    secure = ThreadingHTTPServer(("127.0.0.1", port - 1), handler)
    secure.socket = tls_context().wrap_socket(secure.socket, server_side=True)
    threading.Thread(target=secure.serve_forever, daemon=True).start()
    print(f"Fixture site on http://127.0.0.1:{port}/ and https://127.0.0.1:{port - 1}/")
    server.serve_forever()
