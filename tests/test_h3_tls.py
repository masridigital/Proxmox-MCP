"""H3 red team: TLS pinning against real local TLS servers.

Invariant under test: the Authorization header (and the token) is written only to a
socket whose peer passed verification, and nowhere else (proxy, rebinding target,
downgraded or resumed session, pooled connection after a failure).
"""

import asyncio
import contextlib
import datetime
import hashlib
import ipaddress
import logging
import socket
import ssl
from types import SimpleNamespace

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


def _make_cert(d, stem):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"pve-{stem}.test")])
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
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.IPAddress(ipaddress.ip_address("::1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_pem = d / f"{stem}.pem"
    key_pem = d / f"{stem}.key"
    cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_pem.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    fp = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return SimpleNamespace(cert=str(cert_pem), key=str(key_pem), fp=fp)


@pytest.fixture(scope="module")
def certs(tmp_path_factory):
    d = tmp_path_factory.mktemp("h3tls")
    return SimpleNamespace(good=_make_cert(d, "good"), evil=_make_cert(d, "evil"))


@contextlib.asynccontextmanager
async def tls_server(cert, *, host="127.0.0.1", tweak=None, keepalive=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert.cert, cert.key)
    state = SimpleNamespace(received=[], sni=[], handshakes=0)

    def sni_cb(sslobj, server_name, _ctx):
        state.sni.append(server_name)

    ctx.sni_callback = sni_cb
    if tweak:
        tweak(ctx)

    async def handle(reader, writer):
        state.handshakes += 1
        while True:
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    chunk = await asyncio.wait_for(reader.read(4096), 2)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
            state.received.append(data)
            if b"\r\n\r\n" not in data:
                break
            body = b'{"data":"ok"}'
            conn = b"keep-alive" if keepalive else b"close"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: "
                + conn
                + b"\r\n\r\n"
                + body
            )
            await writer.drain()
            if not keepalive:
                break
        writer.close()

    srv = await asyncio.start_server(handle, host, 0, ssl=ctx)
    state.port = srv.sockets[0].getsockname()[1]
    try:
        yield state
    finally:
        srv.close()
        await srv.wait_closed()


def make_client(monkeypatch, port, *, host="127.0.0.1", pin="", ca="", insecure=False):
    monkeypatch.setattr(client_mod, "PROXMOX_HOST", host)
    monkeypatch.setattr(client_mod, "PROXMOX_PORT", str(port))
    monkeypatch.setattr(client_mod, "PROXMOX_TLS_FINGERPRINT", pin)
    monkeypatch.setattr(client_mod, "PROXMOX_CA_BUNDLE", ca)
    monkeypatch.setattr(client_mod, "PROXMOX_INSECURE_TLS", insecure)
    monkeypatch.setattr(client_mod, "PROXMOX_READ_ONLY", False)
    monkeypatch.setattr(
        client_mod, "require_identity", lambda: Identity("alice@example.com", "user")
    )
    monkeypatch.setattr(client_mod.ProxmoxClient, "resolve_auth", lambda self, i: ("ro", TOKEN))
    monkeypatch.setattr(client_mod.audit, "audit_event", lambda **f: None)
    return client_mod.ProxmoxClient()


def leaked(state):
    return any(b"Authorization" in r or SECRET.encode() in r for r in state.received)


# --- protocol downgrade ---------------------------------------------------------------------


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1])
async def test_old_tls_versions_refused_even_with_correct_pin(monkeypatch, certs, version):
    def tweak(ctx):
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.maximum_version = version
        with contextlib.suppress(ssl.SSLError):
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")

    async with tls_server(certs.good, tweak=tweak) as srv:
        c = make_client(monkeypatch, srv.port, pin=certs.good.fp)
        try:
            with pytest.raises(httpx.ConnectError):
                await c.get("/version")
        finally:
            await c.close()
        await asyncio.sleep(0.1)
        assert not leaked(srv)


@pytest.mark.parametrize("mode", ["ca", "pin", "insecure"])
def test_context_hardening_in_every_mode(certs, mode, monkeypatch, tmp_path):
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    args = {
        "ca": (certs.good.cert, (), False),
        "pin": ("", (bytes.fromhex(certs.good.fp),), False),
        "insecure": ("", (), True),
    }[mode]
    ctx = client_mod.build_ssl_context(*args)
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.options & ssl.OP_NO_RENEGOTIATION
    assert ctx.keylog_filename is None


async def test_sslkeylogfile_env_never_receives_session_keys(monkeypatch, certs, tmp_path):
    keylog = tmp_path / "keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    async with tls_server(certs.good) as srv:
        c = make_client(monkeypatch, srv.port, host="localhost", ca=certs.good.cert)
        try:
            assert await c.get("/version") == {"data": "ok"}
        finally:
            await c.close()
    assert not keylog.exists()


# --- session resumption / reuse ----------------------------------------------------------------


def test_resumed_session_refused():
    class FakeSSL:
        session_reused = True

        def version(self):
            return "TLSv1.3"

        def getpeercert(self, binary_form=False):
            return b"cert"

    class FakeStream(httpcore.AsyncNetworkStream):
        def get_extra_info(self, info):
            return FakeSSL() if info == "ssl_object" else None

    pin = hashlib.sha256(b"cert").digest()
    with pytest.raises(client_mod.TLSVerificationError, match="resumption"):
        client_mod._check_peer(FakeStream(), (pin,))


async def test_every_connection_is_a_full_verified_handshake(monkeypatch, certs):
    checks = []
    real = client_mod._check_peer

    def spy(stream, pins):
        checks.append(stream.get_extra_info("ssl_object").session_reused)
        return real(stream, pins)

    monkeypatch.setattr(client_mod, "_check_peer", spy)
    async with tls_server(certs.good) as srv:
        c = make_client(monkeypatch, srv.port, pin=certs.good.fp)
        try:
            for _ in range(3):
                await c.get("/version")  # server closes: three connections
        finally:
            await c.close()
    assert checks == [False, False, False]
    assert srv.handshakes == 3


async def test_no_connection_is_pooled_after_a_pin_failure(monkeypatch, certs):
    async with tls_server(certs.evil) as srv:
        c = make_client(monkeypatch, srv.port, pin=certs.good.fp)
        try:
            for _ in range(2):
                with pytest.raises(httpx.ConnectError, match="fingerprint mismatch"):
                    await c.get("/version")
                assert c.client._transport._pool.connections == []
        finally:
            await c.close()
        await asyncio.sleep(0.1)
        assert srv.handshakes == 2 and not leaked(srv)


async def test_keepalive_reuses_only_the_verified_connection(monkeypatch, certs):
    async with tls_server(certs.good, keepalive=True) as srv:
        c = make_client(monkeypatch, srv.port, pin=certs.good.fp)
        try:
            for _ in range(3):
                await c.get("/version")
        finally:
            await c.close()
    assert srv.handshakes == 1 and sum(b"Authorization" in r for r in srv.received) == 3


# --- identity of the peer: SNI, Host, CA+pin, IPv6, rebinding -------------------------------------


async def test_sni_and_host_header_match_configured_host(monkeypatch, certs):
    async with tls_server(certs.good) as srv:
        c = make_client(monkeypatch, srv.port, host="localhost", ca=certs.good.cert)
        try:
            await c.get("/version")
        finally:
            await c.close()
    assert srv.sni == ["localhost"]
    assert f"Host: localhost:{srv.port}\r\n".encode() in srv.received[0]


async def test_ip_literal_sends_no_sni_and_verifies_ip_san(monkeypatch, certs):
    async with tls_server(certs.good) as srv:
        c = make_client(monkeypatch, srv.port, host="127.0.0.1", ca=certs.good.cert)
        try:
            await c.get("/version")
        finally:
            await c.close()
    assert srv.sni == [None]
    assert f"Host: 127.0.0.1:{srv.port}\r\n".encode() in srv.received[0]


async def test_ca_bundle_with_correct_pin_succeeds(monkeypatch, certs):
    async with tls_server(certs.good) as srv:
        c = make_client(
            monkeypatch, srv.port, host="localhost", ca=certs.good.cert, pin=certs.good.fp
        )
        try:
            assert await c.get("/version") == {"data": "ok"}
        finally:
            await c.close()


async def test_ca_bundle_hostname_mismatch_refused_even_with_correct_pin(monkeypatch, certs):
    async with tls_server(certs.good) as srv:
        # "127.0.0.2" is not in the SAN; with a CA bundle the hostname check stays on.
        monkeypatch.setattr(
            client_mod.httpcore.AnyIOBackend, "connect_tcp", _redirect_to(srv.port, "127.0.0.1")
        )
        c = make_client(
            monkeypatch, srv.port, host="127.0.0.2", ca=certs.good.cert, pin=certs.good.fp
        )
        try:
            with pytest.raises(httpx.ConnectError):
                await c.get("/version")
        finally:
            await c.close()
        await asyncio.sleep(0.1)
        assert not leaked(srv)


def _redirect_to(port, host="127.0.0.1"):
    real = httpcore.AnyIOBackend.connect_tcp

    async def connect_tcp(
        self, _host, _port, timeout=None, local_address=None, socket_options=None
    ):
        return await real(
            self,
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    return connect_tcp


def _ipv6_available():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _ipv6_available(), reason="no IPv6 loopback")
@pytest.mark.parametrize("mode", ["pin", "ca"])
async def test_ipv6_literal_host(monkeypatch, certs, mode):
    async with tls_server(certs.good, host="::1") as srv:
        kwargs = {"pin": certs.good.fp} if mode == "pin" else {"ca": certs.good.cert}
        c = make_client(monkeypatch, srv.port, host="::1", **kwargs)
        try:
            assert await c.get("/version") == {"data": "ok"}
        finally:
            await c.close()
    assert f"Host: [::1]:{srv.port}\r\n".encode() in srv.received[0]


@pytest.mark.parametrize("mode", ["pin", "ca"])
async def test_dns_rebinding_to_another_peer_never_gets_the_token(
    monkeypatch, certs, mode, tmp_path
):
    # The name resolves to the attacker between connects. The attacker's cert is valid
    # for the name but chains to nothing we trust and has another fingerprint. Even with
    # SSL_CERT_FILE pointing at the attacker's cert, a configured CA bundle wins.
    monkeypatch.setenv("SSL_CERT_FILE", certs.evil.cert)
    async with tls_server(certs.good) as good, tls_server(certs.evil) as evil:
        kwargs = {"pin": certs.good.fp} if mode == "pin" else {"ca": certs.good.cert}
        c = make_client(monkeypatch, good.port, host="localhost", **kwargs)
        try:
            assert await c.get("/version") == {"data": "ok"}
            await c.client.aclose()  # drop the pool: the next request reconnects
            c = make_client(monkeypatch, good.port, host="localhost", **kwargs)
            monkeypatch.setattr(
                client_mod.httpcore.AnyIOBackend, "connect_tcp", _redirect_to(evil.port)
            )
            with pytest.raises(httpx.ConnectError):
                await c.get("/version")
        finally:
            await c.close()
        await asyncio.sleep(0.1)
        assert evil.sni == ["localhost"]  # the client did reach the rebound peer...
        assert not leaked(evil)  # ...and wrote nothing to it


# --- proxies, redirects ----------------------------------------------------------------------------


async def test_proxy_environment_is_ignored(monkeypatch, certs):
    proxy_hits = []

    async def proxy_handler(reader, writer):
        proxy_hits.append(await reader.read(4096))
        writer.close()

    proxy = await asyncio.start_server(proxy_handler, "127.0.0.1", 0)
    proxy_url = f"http://127.0.0.1:{proxy.sockets[0].getsockname()[1]}"
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(var, proxy_url)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    try:
        async with tls_server(certs.good) as srv:
            c = make_client(monkeypatch, srv.port, pin=certs.good.fp)
            try:
                assert await c.get("/version") == {"data": "ok"}
            finally:
                await c.close()
    finally:
        proxy.close()
        await proxy.wait_closed()
    assert proxy_hits == []
    assert c.client._mounts == {}


# --- logging across TLS failures ---------------------------------------------------------------------


async def test_tls_failures_log_no_secret(monkeypatch, certs, caplog):
    root = logging.getLogger()
    old = root.level
    root.setLevel(logging.DEBUG)
    # Another test may have run http_app.main(), which quiets these loggers process-wide.
    for name in ("httpx", "httpcore"):
        monkeypatch.setattr(logging.getLogger(name), "level", logging.DEBUG)
    try:
        with caplog.at_level(logging.DEBUG):
            async with tls_server(certs.evil) as srv:
                c = make_client(monkeypatch, srv.port, pin=certs.good.fp)
                try:
                    with pytest.raises(httpx.ConnectError) as ei:
                        await c.get("/version", {"q": "QSMARKER"})
                finally:
                    await c.close()
            async with tls_server(certs.good) as srv:
                c = make_client(monkeypatch, srv.port, pin=certs.good.fp)
                try:
                    await c.get("/version", {"q": "QSMARKER"})
                finally:
                    await c.close()
    finally:
        root.setLevel(old)
    text = "\n".join(f"{r.name} {r.getMessage()}" for r in caplog.records)
    assert caplog.records  # httpx/httpcore did log at DEBUG
    assert SECRET not in text and "PVEAPIToken" not in text and "QSMARKER" not in text
    assert SECRET not in str(ei.value) and "authorization" not in {
        k.lower() for k in ei.value.request.headers
    }
