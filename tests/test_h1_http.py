"""H1 red team: request handling at the broker's ASGI edge.

Framing (Content-Length / Transfer-Encoding / Content-Encoding), path and Host
tricks, header duplication, pre-auth resource use, slow bodies, uniform errors,
uvicorn settings, and identity isolation under concurrency.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
import uuid

import anyio
import httpx
import jwt
import pytest
from starlette.testclient import TestClient
from test_http_guard import (  # noqa: F401  (env is a fixture)
    SERVICE_ID,
    USER,
    WORKER_KEY,
    Jwks,
    access_token,
    assertion,
    build,
    env,
)

from proxmox_mcp.identity import Identity, current_identity
from proxmox_mcp.transport import IDENTITY_SCOPE_KEY, http_app
from proxmox_mcp.transport.access_jwt import AccessVerifier
from proxmox_mcp.transport.http_app import BrokerAuth, HttpSettings, create_app
from proxmox_mcp.transport.identity_assertion import IdentityAssertionVerifier

BOB = "bob@example.com"


@pytest.fixture
def client(env):  # noqa: F811
    with TestClient(build(), raise_server_exceptions=False) as c:
        yield c


def body_of(payload) -> bytes:
    return json.dumps(payload).encode()


def auth_headers(body: bytes, method="POST", path="/v1/execute", **claims) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "cf-access-jwt-assertion": access_token(),
        "x-mcp-identity": assertion(body, method, path, **claims),
    }


# ---- raw ASGI driver ----------------------------------------------------------


async def asgi_call(
    app,
    *,
    method="POST",
    path="/v1/execute",
    raw_path=None,
    headers=(),
    body=b"",
    hang=False,
    timeout=5.0,
):
    """Drive the app with a hand-built scope; returns (status, headers, body)."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": raw_path if raw_path is not None else path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8765),
    }
    sent: list[dict] = []
    delivered = False

    async def receive():
        nonlocal delivered
        if hang:
            await anyio.sleep_forever()
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}
        await anyio.sleep_forever()

    async def send(message):
        sent.append(message)

    with anyio.fail_after(timeout):
        await app(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    payload = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), payload


def raw_app(env, **settings_kw):  # noqa: F811
    settings = HttpSettings(allowed_hosts=("testserver",), max_request_bytes=4096, **settings_kw)
    access = AccessVerifier(
        "https://team.cloudflareaccess.com",
        "b" * 64,
        service_client_ids=[SERVICE_ID],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(Jwks().handler)),
    )
    return create_app(
        settings,
        access_verifier=access,
        assertion_verifier=IdentityAssertionVerifier(WORKER_KEY.public_key()),
    )


# ---- framing --------------------------------------------------------------------


@pytest.mark.parametrize(
    "length",
    [
        "\xb2",  # SUPERSCRIPT TWO: str.isdigit() is True, int() raises
        pytest.param("9" * 5000, id="5000-digits"),  # int() refuses > 4300 digits
        "+12",
        " 12",
        "1_0",
        "-1",
    ],
)
async def test_bad_content_length_is_400_not_500(env, length):  # noqa: F811
    app = raw_app(env)
    status, _, _ = await asgi_call(
        app, headers=[("host", "testserver"), ("content-length", length)]
    )
    assert status == 400


async def test_content_length_and_transfer_encoding_conflict(env):  # noqa: F811
    app = raw_app(env)
    body = body_of({"tool": "list_nodes"})
    h = auth_headers(body)
    status, _, _ = await asgi_call(
        app,
        body=body,
        headers=[
            ("host", "testserver"),
            ("content-length", str(len(body))),
            ("transfer-encoding", "chunked"),
            *h.items(),
        ],
    )
    assert status == 400


@pytest.mark.parametrize("te", ["gzip, chunked", "identity", "chunked, chunked", "xchunked"])
async def test_transfer_encoding_other_than_chunked(env, te):  # noqa: F811
    app = raw_app(env)
    status, _, _ = await asgi_call(app, headers=[("host", "testserver"), ("transfer-encoding", te)])
    assert status == 400


@pytest.mark.parametrize("ce", ["gzip", "deflate", "br", "identity, gzip"])
def test_content_encoding_refused(client, ce):
    """The body hash is over the bytes on the wire; the broker never inflates.
    Make that explicit instead of failing later as 'bad JSON'."""
    body = body_of({"tool": "list_nodes"})
    h = auth_headers(body)
    h["content-encoding"] = ce
    assert client.post("/v1/execute", content=body, headers=h).status_code == 415


def test_content_encoding_identity_allowed(client):
    body = body_of({"tool": "list_nodes"})
    h = auth_headers(body)
    h["content-encoding"] = "identity"
    assert client.post("/v1/execute", content=body, headers=h).status_code == 200


# ---- path / host / method tricks --------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [b"/v1%2Fexecute", b"/v1/%65xecute", b"/v1/execute%00", b"/%761/execute"],
)
async def test_percent_encoded_paths_refused(env, raw):  # noqa: F811
    """uvicorn hands the app the DECODED path; refuse any request whose raw
    target differs from the canonical route so the signed path is the wire path."""
    app = raw_app(env)
    body = body_of({"tool": "list_nodes"})
    from urllib.parse import unquote

    status, _, _ = await asgi_call(
        app,
        path=unquote(raw.decode()),
        raw_path=raw,
        body=body,
        headers=[("host", "testserver"), *auth_headers(body).items()],
    )
    assert status == 404


@pytest.mark.parametrize(
    "path",
    ["/v1/execute/", "//v1/execute", "/v1/./execute", "/v1/../v1/execute", "/V1/EXECUTE", "*"],
)
async def test_path_variants_404(env, path):  # noqa: F811
    status, _, _ = await asgi_call(raw_app(env), path=path, headers=[("host", "testserver")])
    assert status == 404


async def test_absolute_form_target_404(env):  # noqa: F811
    # h11 leaves an absolute-form target in the path; it must not route.
    status, _, _ = await asgi_call(
        raw_app(env), path="http://testserver/v1/execute", headers=[("host", "testserver")]
    )
    assert status == 404


@pytest.mark.parametrize(
    "host",
    ["user@testserver", "testserver.", "testserver:80@evil", "evil\ttestserver", "testserver:"],
)
def test_host_tricks(client, host):
    body = body_of({"tool": "list_nodes"})
    h = auth_headers(body)
    h["host"] = host
    assert client.post("/v1/execute", content=body, headers=h).status_code in (400, 421)


async def test_duplicate_host_header(env):  # noqa: F811
    status, _, _ = await asgi_call(
        raw_app(env), headers=[("host", "testserver"), ("host", "evil.example.com")]
    )
    assert status == 400


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "PUT", "DELETE", "TRACE"])
def test_other_methods(client, method):
    r = client.request(method, "/v1/execute")
    assert r.status_code == 405


@pytest.mark.parametrize("method", ["post", "Post", "POST ", "CONNECT"])
async def test_method_case_and_garbage(env, method):  # noqa: F811
    # httpx upper-cases methods, so drive the scope directly as h11 would.
    status, _, _ = await asgi_call(raw_app(env), method=method, headers=[("host", "testserver")])
    assert status == 405


def test_head_catalog_is_405(client):
    assert client.head("/v1/catalog").status_code == 405


# ---- headers ---------------------------------------------------------------------


async def test_too_many_headers_431(env):  # noqa: F811
    headers = [("host", "testserver")] + [(f"x-h{i}", "v") for i in range(200)]
    status, _, _ = await asgi_call(raw_app(env), method="GET", path="/healthz", headers=headers)
    assert status == 431


async def test_oversize_header_block_431(env):  # noqa: F811
    headers = [("host", "testserver"), ("x-pad", "a" * (40 * 1024))]
    status, _, _ = await asgi_call(raw_app(env), method="GET", path="/v1/catalog", headers=headers)
    assert status == 431


async def test_duplicate_identity_headers_refused(env):  # noqa: F811
    app = raw_app(env)
    body = body_of({"tool": "list_nodes"})
    good = assertion(body, "POST", "/v1/execute")
    other = assertion(body, "POST", "/v1/execute", sub=BOB)
    status, _, _ = await asgi_call(
        app,
        body=body,
        headers=[
            ("host", "testserver"),
            ("content-type", "application/json"),
            ("cf-access-jwt-assertion", access_token()),
            ("x-mcp-identity", good),
            ("X-MCP-Identity", other),
        ],
    )
    assert status == 401


async def test_duplicate_access_headers_refused(env):  # noqa: F811
    app = raw_app(env)
    body = body_of({"tool": "list_nodes"})
    status, _, _ = await asgi_call(
        app,
        body=body,
        headers=[
            ("host", "testserver"),
            ("content-type", "application/json"),
            ("cf-access-jwt-assertion", access_token()),
            ("Cf-Access-Jwt-Assertion", access_token()),
            ("x-mcp-identity", assertion(body, "POST", "/v1/execute")),
        ],
    )
    assert status == 401


def test_cf_ray_injection_not_trusted(client, env, caplog):  # noqa: F811
    """A bogus Cf-Ray must not reach logs verbatim (log forging)."""
    body = body_of({"tool": "list_nodes"})
    h = auth_headers(body)
    h["x-mcp-identity"] = "garbage"
    h["cf-ray"] = "abc INJECTED"  # not representable? use latin-1 safe forge below
    h["cf-ray"] = "abc INJECTED=1"
    with caplog.at_level("INFO"):
        assert client.post("/v1/execute", content=body, headers=h).status_code == 401
    assert "INJECTED" not in caplog.text


def test_tool_name_trailing_newline_is_400(client):
    payload = b'{"tool": "list_nodes\\n", "arguments": {}}'
    assert (
        client.post("/v1/execute", content=payload, headers=auth_headers(payload)).status_code
        == 400
    )


# ---- uniform errors ---------------------------------------------------------------


def test_auth_failures_are_indistinguishable(client):
    """Every authentication failure gives the same status, body and headers."""
    body = body_of({"tool": "list_nodes"})
    variants = []
    variants.append({"content-type": "application/json"})  # nothing
    h = auth_headers(body)
    h["cf-access-jwt-assertion"] = access_token(aud=["c" * 64])
    variants.append(h)
    h = auth_headers(body)
    h["cf-access-jwt-assertion"] = access_token(common_name="other.access")
    variants.append(h)
    h = auth_headers(body)
    h["x-mcp-identity"] = assertion(body, "POST", "/v1/catalog")
    variants.append(h)
    h = auth_headers(body)
    h["x-mcp-identity"] = h["x-mcp-identity"] + "=="
    variants.append(h)
    h = auth_headers(body)
    old = int(time.time()) - 600
    h["x-mcp-identity"] = assertion(body, "POST", "/v1/execute", iat=old, exp=old + 60)
    variants.append(h)
    seen = set()
    for headers in variants:
        r = client.post("/v1/execute", content=body, headers=headers)
        assert r.status_code == 401
        seen.add((r.content, tuple(sorted((k, v) for k, v in r.headers.items()))))
    assert len(seen) == 1


# ---- pre-auth resource use and slow clients --------------------------------------


async def test_unauthenticated_request_does_not_wait_for_body(env):  # noqa: F811
    """Without a valid Access token the broker answers 401 without reading
    (buffering, waiting for) the request body."""
    status, _, _ = await asgi_call(
        raw_app(env),
        headers=[("host", "testserver"), ("content-type", "application/json")],
        hang=True,
        timeout=2.0,
    )
    assert status == 401


async def test_missing_assertion_does_not_wait_for_body(env):  # noqa: F811
    status, _, _ = await asgi_call(
        raw_app(env),
        headers=[
            ("host", "testserver"),
            ("content-type", "application/json"),
            ("cf-access-jwt-assertion", access_token()),
        ],
        hang=True,
        timeout=2.0,
    )
    assert status == 401


async def test_slow_body_times_out_with_408(env):  # noqa: F811
    """Slowloris on the body: an authenticated-looking request that never
    finishes its body is cut off by the body timeout, not the 120 s tool timeout."""
    app = raw_app(env, body_timeout=0.2)
    status, _, _ = await asgi_call(
        app,
        headers=[
            ("host", "testserver"),
            ("content-type", "application/json"),
            ("cf-access-jwt-assertion", access_token()),
            ("x-mcp-identity", assertion(b"{}", "POST", "/v1/execute")),
        ],
        hang=True,
        timeout=3.0,
    )
    assert status == 408


def test_body_timeout_setting(monkeypatch):
    monkeypatch.setenv("MCP_BODY_TIMEOUT", "7")
    assert HttpSettings.from_env().body_timeout == 7.0
    monkeypatch.setenv("MCP_BODY_TIMEOUT", "0")
    with pytest.raises(http_app.ConfigError):
        HttpSettings.from_env()


# ---- uvicorn configuration ----------------------------------------------------------


def test_uvicorn_settings(monkeypatch, env):  # noqa: F811
    import uvicorn

    captured: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(kw))
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "127.0.0.1:8765")
    monkeypatch.setenv("BROKER_REQUIRE_ACCESS_JWT", "0")
    monkeypatch.setattr(
        http_app.IdentityAssertionVerifier,
        "from_credentials",
        classmethod(lambda cls: IdentityAssertionVerifier(WORKER_KEY.public_key())),
    )
    from proxmox_mcp import server

    monkeypatch.setattr(server, "_validate_config", lambda role="stdio": None)
    http_app.main()
    # Pin the pure-Python h11 parser: strict framing (rejects CL+TE, bad
    # Content-Length), and h11_max_incomplete_event_size actually applies. With
    # http="auto" an installed httptools would silently replace it.
    from uvicorn.protocols.http.h11_impl import H11Protocol

    assert isinstance(captured["http"], type) and issubclass(captured["http"], H11Protocol)
    assert captured["h11_max_incomplete_event_size"] <= 32 * 1024
    assert captured["proxy_headers"] is False
    assert captured["forwarded_allow_ips"] == ""
    assert captured["server_header"] is False
    assert captured["ws"] == "none"
    assert captured["timeout_keep_alive"] <= 5
    assert captured["limit_concurrency"] >= 1
    assert captured["host"] == "127.0.0.1"


# ---- identity isolation ----------------------------------------------------------------


def _assert_for(user: str, body: bytes) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": "proxmox-mcp-worker",
            "aud": "proxmox-broker",
            "sub": user,
            "iat": now,
            "exp": now + 60,
            "jti": str(uuid.uuid4()),
            "req": hashlib.sha256(body).hexdigest(),
            "method": "POST",
            "path": "/v1/execute",
        },
        WORKER_KEY,
        algorithm="EdDSA",
    )


def _probe_app(record: list):
    async def endpoint(scope, body, send):
        claimed = json.loads(body)["who"]
        for _ in range(5):
            await asyncio.sleep(0)  # let every other request interleave here
            await asyncio.sleep(0.001)
            ctx = current_identity.get()
            record.append(
                (claimed, ctx.subject if ctx else None, scope[IDENTITY_SCOPE_KEY].subject)
            )
        if claimed == "boom":
            raise RuntimeError("endpoint failure")
        await http_app._send_json(send, 200, {"ok": True})

    return BrokerAuth(
        endpoint,
        assertion_verifier=IdentityAssertionVerifier(WORKER_KEY.public_key()),
        access_verifier=None,
        enrollment_check=lambda ident: None,
    )


async def test_no_identity_bleed_under_concurrency():
    record: list = []
    app = _probe_app(record)
    users = [USER, BOB] * 50

    async def one(user: str) -> int:
        body = json.dumps({"who": user}).encode()
        status, _, _ = await asgi_call(
            app, body=body, headers=[("x-mcp-identity", _assert_for(user, body))]
        )
        return status

    statuses = await asyncio.gather(*(one(u) for u in users))
    assert statuses == [200] * len(users)
    assert len(record) == 5 * len(users)
    assert all(claimed == ctx == sc for claimed, ctx, sc in record)
    assert current_identity.get() is None


async def test_identity_reset_after_endpoint_exception_in_same_task():
    """Sequential requests in ONE task (no fresh context per request): the
    ContextVar must be cleared even when the endpoint raises."""
    record: list = []
    app = _probe_app(record)
    body = json.dumps({"who": "boom"}).encode()
    with pytest.raises(RuntimeError):
        await asgi_call(
            app, body=body, headers=[("x-mcp-identity", _assert_for("x@example.com", body))]
        )
    assert current_identity.get() is None
    body = json.dumps({"who": BOB}).encode()
    status, _, _ = await asgi_call(
        app, body=body, headers=[("x-mcp-identity", _assert_for(BOB, body))]
    )
    assert status == 200 and current_identity.get() is None


async def test_preseeded_scope_identity_is_ignored(env):  # noqa: F811
    """An identity already sitting in the scope (another middleware, a test
    harness, a future refactor) is never honoured; auth still runs."""
    app = raw_app(env)
    scope_identity = Identity(subject=USER, kind="user", email=USER)

    class Seeding:
        async def __call__(self, scope, receive, send):
            scope[IDENTITY_SCOPE_KEY] = scope_identity
            await app(scope, receive, send)

    status, _, _ = await asgi_call(
        Seeding(), method="GET", path="/v1/catalog", headers=[("host", "testserver")]
    )
    assert status == 401
