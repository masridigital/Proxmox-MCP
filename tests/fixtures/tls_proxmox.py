"""A local HTTPS server with a self-signed certificate that answers like Proxmox.

Runs in a thread (independent of any event loop), binds 127.0.0.1 on a free
port, and records method, path and Authorization of every request it parses.
A connection whose TLS handshake the client aborts never reaches the handler,
so ``requests`` stays empty: that is how the tests prove nothing was sent.
"""

from __future__ import annotations

import datetime
import hashlib
import http.server
import ipaddress
import json
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .mock_proxmox import API_PREFIX, response_for


def make_self_signed(directory: Path) -> tuple[Path, Path, str]:
    """(cert.pem, key.pem, sha256 hex of the DER certificate) for 127.0.0.1."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pve.example.internal")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = directory / "pve-cert.pem"
    key_pem = directory / "pve-key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert_pem, key_pem, fingerprint


@dataclass
class TlsProxmox:
    port: int
    fingerprint: str
    requests: list[tuple[str, str, str | None]] = field(default_factory=list)


@contextmanager
def tls_proxmox(directory: Path) -> Iterator[TlsProxmox]:
    cert_pem, key_pem, fingerprint = make_self_signed(directory)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_pem, key_pem)
    state = TlsProxmox(port=0, fingerprint=fingerprint)

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self) -> None:
            path = self.path.partition("?")[0]
            state.requests.append((self.command, path, self.headers.get("Authorization")))
            api_path = path[len(API_PREFIX) :] if path.startswith(API_PREFIX) else path
            body = json.dumps(response_for(self.command, api_path)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = _answer  # noqa: N815

        def log_message(self, *args: object) -> None:
            pass

    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True

        def get_request(self):  # TLS per connection; a failed handshake drops it
            sock, addr = super().get_request()
            return ctx.wrap_socket(sock, server_side=True), addr

        def handle_error(self, request, client_address) -> None:
            pass

    httpd = Server(("127.0.0.1", 0), Handler)
    state.port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(5)
