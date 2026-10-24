"""TLS verification against a real local TLS server with a self-signed certificate.

The key property: with a wrong pin (or an unverifiable chain) the server never
receives a single request byte, so the Authorization header cannot leak.
"""

import asyncio
import datetime
import hashlib
import ipaddress
import logging
import ssl

import httpcore
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from proxmox_mcp import client as client_mod
from proxmox_mcp.credentials import parse_api_token
from proxmox_mcp.identity import Identity

SECRET = "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"
TOKEN = parse_api_token(f"mcp-alice@pve!mcp={SECRET}")


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    d = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pve.test")])
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
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = d / "cert.pem"
    key_pem = d / "key.pem"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return str(cert_pem), str(key_pem), fingerprint


@pytest.fixture
async def server(cert_files):
    cert_pem, key_pem, _ = cert_files
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_pem, key_pem)
    received: list[bytes] = []

    async def handle(reader, writer):
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = await asyncio.wait_for(reader.read(4096), 2)
                if not chunk:
                    break
                data += chunk
        except Exception:
            pass
        received.append(data)
        if b"\r\n\r\n" in data:
            body = b'{"data":"ok"}'
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body
            )
            await writer.drain()
        writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = srv.sockets[0].getsockname()[1]
    yield port, received
    srv.close()
    await srv.wait_closed()


def make_client(monkeypatch, port, *, pin="", ca="", insecure=False):
    monkeypatch.setattr(client_mod, "PROXMOX_HOST", "127.0.0.1")
    monkeypatch.setattr(client_mod, "PROXMOX_PORT", str(port))
    monkeypatch.setattr(client_mod, "PROXMOX_TLS_FINGERPRINT", pin)
    monkeypatch.setattr(client_mod, "PROXMOX_CA_BUNDLE", ca)
    monkeypatch.setattr(client_mod, "PROXMOX_INSECURE_TLS", insecure)
    monkeypatch.setattr(client_mod, "PROXMOX_READ_ONLY", False)
    monkeypatch.setattr(client_mod, "require_identity", lambda: Identity("alice@example.com", "user"))
    monkeypatch.setattr(client_mod.ProxmoxClient, "resolve_auth", lambda self, i: ("ro", TOKEN))
    monkeypatch.setattr(client_mod.audit, "audit_event", lambda **f: None)
    return client_mod.ProxmoxClient()


def leaked(received):
    return any(b"Authorization" in r or SECRET.encode() in r for r in received)


async def test_correct_pin_succeeds(monkeypatch, server, cert_files):
    port, received = server
    c = make_client(monkeypatch, port, pin=cert_files[2])
    try:
        assert await c.get("/version") == {"data": "ok"}
    finally:
        await c.close()
    assert c.tls_mode == "pinned"
    assert b"Authorization: PVEAPIToken=mcp-alice@pve!mcp=" + SECRET.encode() in received[0]


async def test_pin_with_colons_uppercase(monkeypatch, server, cert_files):
    port, _ = server
    fp = ":".join(cert_files[2][i : i + 2] for i in range(0, 64, 2)).upper()
    c = make_client(monkeypatch, port, pin=f"{'00' * 32},{fp}")  # rotation list
    try:
        assert await c.get("/version") == {"data": "ok"}
    finally:
        await c.close()


async def test_wrong_pin_sends_nothing(monkeypatch, server):
    port, received = server
    c = make_client(monkeypatch, port, pin="ab" * 32)
    try:
        with pytest.raises(httpx.ConnectError, match="fingerprint mismatch"):
            await c.get("/version")
    finally:
        await c.close()
    await asyncio.sleep(0.2)
    # The handshake completed (the server accepted the connection) but no byte followed.
    assert received and all(r == b"" for r in received)
    assert not leaked(received)


async def test_ca_bundle_succeeds(monkeypatch, server, cert_files):
    port, _ = server
    c = make_client(monkeypatch, port, ca=cert_files[0])
    try:
        assert await c.get("/version") == {"data": "ok"}
    finally:
        await c.close()
    assert c.tls_mode == "ca"


async def test_ca_bundle_plus_wrong_pin_fails(monkeypatch, server, cert_files):
    port, received = server
    c = make_client(monkeypatch, port, ca=cert_files[0], pin="cd" * 32)
    try:
        with pytest.raises(httpx.ConnectError):
            await c.get("/version")
    finally:
        await c.close()
    await asyncio.sleep(0.2)
    assert not leaked(received)


async def test_default_verification_rejects_self_signed(monkeypatch, server):
    port, received = server
    c = make_client(monkeypatch, port)
    try:
        with pytest.raises(httpx.ConnectError):
            await c.get("/version")
    finally:
        await c.close()
    await asyncio.sleep(0.2)
    assert not leaked(received)


async def test_insecure_is_explicit_and_loud(monkeypatch, server, caplog):
    port, _ = server
    with caplog.at_level(logging.WARNING, logger="proxmox_mcp.client"):
        c = make_client(monkeypatch, port, insecure=True)
    try:
        assert await c.get("/version") == {"data": "ok"}
    finally:
        await c.close()
    assert c.tls_mode == "insecure"
    assert any("DISABLED" in r.getMessage() for r in caplog.records)


def test_old_verify_ssl_flag_cannot_disable_verification(monkeypatch):
    monkeypatch.setenv("PROXMOX_VERIFY_SSL", "false")
    monkeypatch.setattr(client_mod, "PROXMOX_INSECURE_TLS", False)
    monkeypatch.setattr(client_mod, "PROXMOX_TLS_FINGERPRINT", "")
    monkeypatch.setattr(client_mod, "PROXMOX_CA_BUNDLE", "")
    assert client_mod.ProxmoxClient().tls_mode == "ca"
    ctx = client_mod.build_ssl_context("", (), False)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


async def test_guarded_stream_refuses_plaintext():
    class Inner(httpcore.AsyncNetworkStream):
        async def aclose(self):
            pass

    stream = client_mod._GuardedStream(Inner(), ())
    with pytest.raises(httpcore.ConnectError):
        await stream.write(b"GET / HTTP/1.1\r\n")
    with pytest.raises(httpcore.ConnectError):
        await stream.read(10)


def test_transport_installs_guarded_backend():
    t = client_mod.GuardedTransport(client_mod.build_ssl_context("", (), False), ())
    assert isinstance(t._pool._network_backend, client_mod.GuardedBackend)
