"""H1 red team on the wire: a real uvicorn server with the production options
(``http_app.uvicorn_options``), driven over raw sockets.

Covers what an in-process ASGI client cannot: request smuggling framing,
oversize heads, HTTP/1.1 pipelining across identities, absolute-form targets
and slowloris on the request head.
"""

from __future__ import annotations

import hashlib
import re
import socket
import threading
import time
import uuid

import jwt
import pytest
import uvicorn
from test_http_guard import USER, WORKER_KEY, env  # noqa: F401  (env is a fixture)

from proxmox_mcp.transport.http_app import HttpSettings, create_app, uvicorn_options
from proxmox_mcp.transport.identity_assertion import IdentityAssertionVerifier


def _assertion(sub: str, method: str = "GET", path: str = "/v1/catalog", body: bytes = b"") -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": "proxmox-mcp-worker",
            "aud": "proxmox-broker",
            "sub": sub,
            "iat": now,
            "exp": now + 60,
            "jti": str(uuid.uuid4()),
            "req": hashlib.sha256(body).hexdigest(),
            "method": method,
            "path": path,
        },
        WORKER_KEY,
        algorithm="EdDSA",
        headers={"kid": "k1"},
    )


@pytest.fixture
def server(env):  # noqa: F811
    # VPC mode (no Access JWT) keeps the server self-contained; the identity
    # assertion is mandatory in every mode.
    settings = HttpSettings(
        allowed_hosts=("broker.test",),
        require_access_jwt=False,
        header_timeout=1.0,
        body_timeout=1.0,
        port=0,
    )
    app = create_app(
        settings, assertion_verifier=IdentityAssertionVerifier(WORKER_KEY.public_key())
    )
    opts = uvicorn_options(settings)
    opts.update(lifespan="off", log_level="warning")
    srv = uvicorn.Server(uvicorn.Config(app, **opts))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not srv.started:
        assert time.time() < deadline, "server did not start"
        time.sleep(0.02)
    port = srv.servers[0].sockets[0].getsockname()[1]
    yield port
    srv.should_exit = True
    thread.join(5)


def _connect(port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    return s


def _read_all(s: socket.socket, timeout: float = 3.0) -> bytes:
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            out += chunk
    except TimeoutError:
        pass
    return out


def _statuses(raw: bytes) -> list[int]:
    # Responses follow each other directly on a pipelined connection, so a
    # status line can start right after the previous JSON body.
    return [int(code) for code in re.findall(rb"HTTP/1\.1 (\d{3}) ", raw)]


def _catalog_request(sub: str, *, close: bool = False) -> bytes:
    return (
        b"GET /v1/catalog HTTP/1.1\r\nHost: broker.test\r\n"
        + b"X-MCP-Identity: "
        + _assertion(sub).encode()
        + b"\r\n"
        + (b"Connection: close\r\n" if close else b"")
        + b"\r\n"
    )


def test_wire_baseline(server):
    s = _connect(server)
    s.sendall(_catalog_request(USER, close=True))
    assert _statuses(_read_all(s)) == [200]


def test_pipelined_requests_do_not_share_identity(server):
    """Enrolled user, then an unenrolled one, then the enrolled one again, all
    pipelined on one connection: each is judged on its own assertion."""
    s = _connect(server)
    s.sendall(
        _catalog_request(USER)
        + _catalog_request("mallory@example.com")
        + _catalog_request(USER, close=True)
    )
    assert _statuses(_read_all(s)) == [200, 403, 200]


def test_cl_te_smuggling_refused(server):
    body = b'{"tool":"list_nodes"}'
    smuggled = b"GET /v1/catalog HTTP/1.1\r\nHost: broker.test\r\n\r\n"
    s = _connect(server)
    s.sendall(
        b"POST /v1/execute HTTP/1.1\r\nHost: broker.test\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        b"0\r\n\r\n" + smuggled
    )
    statuses = _statuses(_read_all(s))
    assert statuses and statuses[0] == 400
    assert 200 not in statuses


def test_duplicate_content_length_refused(server):
    s = _connect(server)
    s.sendall(
        b"POST /v1/execute HTTP/1.1\r\nHost: broker.test\r\n"
        b"Content-Length: 2\r\nContent-Length: 20\r\n\r\n{}"
    )
    assert _statuses(_read_all(s))[:1] == [400]


def test_oversize_request_head_refused(server):
    s = _connect(server)
    s.sendall(
        b"GET /v1/catalog HTTP/1.1\r\nHost: broker.test\r\n"
        + b"X-Pad: "
        + b"a" * (40 * 1024)
        + b"\r\n\r\n"
    )  # one burst: h11's incomplete-event cap never sees a partial head
    raw = _read_all(s)
    assert _statuses(raw) == [431]


def test_absolute_form_target_does_not_route(server):
    s = _connect(server)
    s.sendall(
        b"GET http://broker.test/v1/catalog HTTP/1.1\r\nHost: broker.test\r\n"
        b"X-MCP-Identity: " + _assertion(USER).encode() + b"\r\nConnection: close\r\n\r\n"
    )
    assert _statuses(_read_all(s)) == [404]


def test_percent_encoded_route_on_the_wire(server):
    s = _connect(server)
    s.sendall(
        b"GET /v1%2Fcatalog HTTP/1.1\r\nHost: broker.test\r\n"
        b"X-MCP-Identity: " + _assertion(USER).encode() + b"\r\nConnection: close\r\n\r\n"
    )
    assert _statuses(_read_all(s)) == [404]


def test_host_with_userinfo_and_trailing_dot(server):
    for host in (b"user@broker.test", b"broker.test.", b"BROKER.TEST:"):
        s = _connect(server)
        s.sendall(
            b"GET /v1/catalog HTTP/1.1\r\nHost: " + host + b"\r\n"
            b"X-MCP-Identity: " + _assertion(USER).encode() + b"\r\nConnection: close\r\n\r\n"
        )
        assert _statuses(_read_all(s))[0] in (400, 421)


def test_slowloris_partial_head_is_closed(server):
    s = _connect(server)
    s.sendall(b"GET /v1/catalog HTTP/1.1\r\nHost: broker.test\r\n")  # never finishes
    started = time.time()
    assert _read_all(s, timeout=5.0) == b""  # closed by the server, no response
    assert time.time() - started < 4.0


def test_silent_connection_is_closed(server):
    s = _connect(server)
    started = time.time()
    assert _read_all(s, timeout=5.0) == b""
    assert time.time() - started < 4.0


def test_slowloris_dribble_does_not_reset_deadline(server):
    """Sending one byte at a time must not extend the head deadline."""
    s = _connect(server)
    head = b"GET /v1/catalog HTTP/1.1\r\nHost: broker.test\r\nX-Pad: " + b"a" * 200
    started = time.time()
    closed = False
    for byte in head:
        try:
            s.sendall(bytes([byte]))
        except OSError:
            closed = True
            break
        time.sleep(0.05)
        if time.time() - started > 4.0:
            break
    if not closed:
        closed = _read_all(s, timeout=1.0) == b""
    assert closed and time.time() - started < 4.5


def test_slow_body_gets_408(server):
    body = b'{"tool":"list_nodes"}'
    s = _connect(server)
    s.sendall(
        b"POST /v1/execute HTTP/1.1\r\nHost: broker.test\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"X-MCP-Identity: "
        + _assertion(USER, "POST", "/v1/execute", body).encode()
        + b"\r\n\r\n"
        + body[:5]
    )
    assert _statuses(_read_all(s, timeout=4.0)) == [408]


def test_keepalive_second_request_head_also_timed(server):
    s = _connect(server)
    s.sendall(_catalog_request(USER))
    s.settimeout(3)
    first = b""
    while b"\r\n\r\n" not in first:
        first += s.recv(65536)
    head, _, rest = first.partition(b"\r\n\r\n")
    length = int(re.search(rb"content-length: (\d+)", head).group(1))
    while len(rest) < length:  # drain the whole first response
        rest += s.recv(65536)
    assert _statuses(head) == [200]
    s.sendall(b"GET /v1/catalog HTTP/1.1\r\n")  # partial second head
    started = time.time()
    assert _read_all(s, timeout=8.0) == b""
    assert time.time() - started < 6.0
