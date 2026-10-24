"""Broker HTTP guard end to end: Access service token + Worker identity assertion,
Host allowlist, size cap, routes, enrollment, rate limits and the execute pipeline.

Offline: RSA key + mocked JWKS for Access, Ed25519 key for the Worker assertion,
a fake Proxmox client, real enrollment/policy/router/output/audit modules.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from jwt.algorithms import RSAAlgorithm
from starlette.testclient import TestClient

from proxmox_mcp import audit, server
from proxmox_mcp.identity import Identity
from proxmox_mcp.transport import http_app
from proxmox_mcp.transport.access_jwt import AccessVerifier
from proxmox_mcp.transport.http_app import ConfigError, HttpSettings, check_bind, create_app
from proxmox_mcp.transport.identity_assertion import (
    AssertionConfigError,
    AssertionDenied,
    IdentityAssertionVerifier,
    ReplayCache,
    load_public_key,
)
from proxmox_mcp.transport.ratelimit import RateLimited, RateLimiter

TEAM = "https://team.cloudflareaccess.com"
AUD = "b" * 64
SERVICE_ID = "0123456789abcdef.access"
USER = "alice@example.com"

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
WORKER_KEY = ed25519.Ed25519PrivateKey.generate()
FORGER_KEY = ed25519.Ed25519PrivateKey.generate()


# ---- token helpers --------------------------------------------------------


def access_token(**over) -> str:
    now = int(time.time())
    c = {
        "aud": [AUD],
        "common_name": SERVICE_ID,
        "sub": "",
        "iss": TEAM,
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "type": "app",
    }
    c.update(over)
    c = {k: v for k, v in c.items() if v is not None}
    return jwt.encode(c, RSA_KEY, algorithm="RS256", headers={"kid": "k1"})


def assertion(body: bytes, http_method: str, http_path: str, /, key=WORKER_KEY, **over) -> str:
    now = int(time.time())
    c = {
        "iss": "proxmox-mcp-worker",
        "aud": "proxmox-broker",
        "sub": USER,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        "ray": "8f00000000000000-IAD",
        "req": hashlib.sha256(body).hexdigest(),
        "method": http_method,
        "path": http_path,
    }
    c.update(over)
    c = {k: v for k, v in c.items() if v is not None}
    return jwt.encode(c, key, algorithm="EdDSA")


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# ---- fixtures ---------------------------------------------------------------


class FakeProxmox:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.closed = False

    async def get(self, path, params=None):
        self.calls.append(path)
        return {"data": [{"node": "pve1", "status": "online"}]}

    async def close(self):
        self.closed = True


@pytest.fixture
def env(tmp_path, monkeypatch):
    enrollment = tmp_path / "enrollment.json"
    enrollment.write_text(
        json.dumps(
            {
                "users": {
                    USER: {
                        "mode": "ro",
                        "proxmox_userid": "alice@pve",
                        "token_credential": "pve-token-alice",
                    }
                }
            }
        )
    )
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", str(enrollment))
    monkeypatch.setenv("MCP_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.delenv("MCP_TOOL_ALLOW", raising=False)
    monkeypatch.delenv("MCP_TOOL_DENY", raising=False)
    audit.reset_for_tests()
    fake = FakeProxmox()
    monkeypatch.setattr(server, "proxmox", fake)
    monkeypatch.setattr(server, "limiter", RateLimiter(60, 2000))
    yield {"proxmox": fake, "audit": tmp_path / "audit.jsonl"}
    audit.reset_for_tests()


class Jwks:
    def __init__(self) -> None:
        jwk = json.loads(RSAAlgorithm.to_jwk(RSA_KEY.public_key()))
        jwk.update({"kid": "k1", "alg": "RS256", "use": "sig"})
        self.doc = {"keys": [jwk]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=self.doc)


def build(require_access: bool = True, max_bytes: int = 4096, **kw):
    settings = HttpSettings(
        allowed_hosts=("testserver",),
        require_access_jwt=require_access,
        max_request_bytes=max_bytes,
    )
    access = AccessVerifier(
        TEAM,
        AUD,
        service_client_ids=[SERVICE_ID],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(Jwks().handler)),
    )
    verifier = IdentityAssertionVerifier(WORKER_KEY.public_key())
    return create_app(settings, access_verifier=access, assertion_verifier=verifier, **kw)


@pytest.fixture
def client(env):
    with TestClient(build(), raise_server_exceptions=False) as c:
        yield c


def execute(c: TestClient, payload, *, access=True, ident=True, headers=None, **claims):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    h = {"content-type": "application/json"}
    if access:
        h["cf-access-jwt-assertion"] = access_token()
    if ident:
        h["x-mcp-identity"] = assertion(body, "POST", "/v1/execute", **claims)
    h.update(headers or {})
    return c.post("/v1/execute", content=body, headers=h)


def catalog(c: TestClient, **claims):
    h = {
        "cf-access-jwt-assertion": access_token(),
        "x-mcp-identity": assertion(b"", "GET", "/v1/catalog", **claims),
    }
    return c.get("/v1/catalog", headers=h)


def audit_lines(env) -> list[dict]:
    return [json.loads(line) for line in env["audit"].read_text().splitlines()]


# ---- happy paths ---------------------------------------------------------


def test_execute_read_tool(client, env):
    r = execute(client, {"tool": "list_nodes", "arguments": {}})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert "pve1" in body["text"]
    assert env["proxmox"].calls == ["/nodes"]
    lines = [x for x in audit_lines(env) if x.get("target") == "list_nodes"]
    assert [x["side"] for x in lines] == ["in", "out"]
    assert all(x["user"] == USER and x["svc"] == SERVICE_ID and x.get("jti") for x in lines)
    assert lines[0]["ray"] == "8f00000000000000-IAD"


def test_catalog_for_asserted_user(client):
    r = catalog(client)
    assert r.status_code == 200
    doc = r.json()
    assert doc["mode"] == "ro" and len(doc["version"]) == 64
    names = {t["name"] for t in doc["tools"]}
    assert "list_nodes" in names
    assert {t["tier"] for t in doc["tools"]} == {"read"}


def test_security_headers_on_every_response(client):
    for r in (
        client.get("/healthz"),
        client.get("/nope"),
        execute(client, {"tool": "x"}, ident=False),
    ):
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["content-security-policy"].startswith("default-src 'none'")
        assert "server" not in r.headers


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.text == "ok"


def test_lifespan_closes_client(env):
    with TestClient(build()):
        pass
    assert env["proxmox"].closed


# ---- policy through the broker -----------------------------------------------


def test_policy_denial_is_tool_error(client, env):
    r = execute(client, {"tool": "delete_pool", "arguments": {"poolid": "p1"}})
    assert r.status_code == 200
    assert r.json()["ok"] is False and "blocked by policy" in r.json()["text"]
    assert env["proxmox"].calls == []
    denied = [x for x in audit_lines(env) if x.get("target") == "delete_pool"]
    assert [(x["side"], x["status"]) for x in denied] == [("in", "denied")]


def test_unknown_tool_and_invalid_input(client, env):
    r = execute(client, {"tool": "no_such_tool", "arguments": {}})
    assert r.json()["ok"] is False
    r = execute(client, {"tool": "list_nodes", "arguments": {"bogus": 1}})
    assert r.json()["ok"] is False and "Invalid input" in r.json()["text"]
    assert env["proxmox"].calls == []


@pytest.mark.parametrize(
    "payload",
    [
        b"not json",
        b"[]",
        b'{"tool": "list_nodes", "tool": "delete_pool"}',
        b'{"tool": "list_nodes", "arguments": [], "x": 1}',
        b'{"tool": "list_nodes", "arguments": NaN}',
        b'{"tool": "../etc", "arguments": {}}',
        b'{"arguments": {}}',
    ],
)
def test_malformed_execute_body(client, payload):
    assert execute(client, payload).status_code == 400


def test_execute_requires_json_content_type(client):
    r = execute(client, {"tool": "list_nodes"}, headers={"content-type": "text/plain"})
    assert r.status_code == 415


# ---- authentication -----------------------------------------------------------


def test_missing_both(client):
    r = client.post("/v1/execute", json={"tool": "list_nodes"})
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert r.json() == {"error": "unauthorized"}


def test_access_jwt_present_assertion_missing(client):
    assert execute(client, {"tool": "list_nodes"}, ident=False).status_code == 401


def test_assertion_present_access_jwt_missing(client):
    assert execute(client, {"tool": "list_nodes"}, access=False).status_code == 401


def test_access_user_token_is_not_the_worker(client):
    body = json.dumps({"tool": "list_nodes"}).encode()
    r = client.post(
        "/v1/execute",
        content=body,
        headers={
            "content-type": "application/json",
            "cf-access-jwt-assertion": access_token(common_name=None, email=USER),
            "x-mcp-identity": assertion(body, "POST", "/v1/execute"),
        },
    )
    assert r.status_code == 401


def test_access_wrong_service_id(client):
    body = json.dumps({"tool": "list_nodes"}).encode()
    r = client.post(
        "/v1/execute",
        content=body,
        headers={
            "content-type": "application/json",
            "cf-access-jwt-assertion": access_token(common_name="someone-else.access"),
            "x-mcp-identity": assertion(body, "POST", "/v1/execute"),
        },
    )
    assert r.status_code == 401


def test_access_wrong_aud(client):
    body = json.dumps({"tool": "list_nodes"}).encode()
    r = client.post(
        "/v1/execute",
        content=body,
        headers={
            "content-type": "application/json",
            "cf-access-jwt-assertion": access_token(aud=["c" * 64]),
            "x-mcp-identity": assertion(body, "POST", "/v1/execute"),
        },
    )
    assert r.status_code == 401


def test_assertion_forged_with_other_ed25519_key(client, env):
    r = execute(client, {"tool": "list_nodes"}, key=FORGER_KEY)
    assert r.status_code == 401
    assert env["proxmox"].calls == []


def test_assertion_wrong_body_hash(client):
    r = execute(client, {"tool": "list_nodes"}, req=hashlib.sha256(b"other").hexdigest())
    assert r.status_code == 401


def test_assertion_bound_to_body(client):
    """An assertion captured for one body cannot carry another."""
    good = json.dumps({"tool": "list_nodes"}).encode()
    evil = json.dumps({"tool": "list_pools"}).encode()
    r = client.post(
        "/v1/execute",
        content=evil,
        headers={
            "content-type": "application/json",
            "cf-access-jwt-assertion": access_token(),
            "x-mcp-identity": assertion(good, "POST", "/v1/execute"),
        },
    )
    assert r.status_code == 401


def test_assertion_wrong_method_or_path(client):
    assert execute(client, {"tool": "list_nodes"}, path="/v1/catalog").status_code == 401
    assert execute(client, {"tool": "list_nodes"}, method="GET").status_code == 401


def test_assertion_replay(client):
    body = json.dumps({"tool": "list_nodes"}).encode()
    headers = {
        "content-type": "application/json",
        "cf-access-jwt-assertion": access_token(),
        "x-mcp-identity": assertion(body, "POST", "/v1/execute"),
    }
    assert client.post("/v1/execute", content=body, headers=headers).status_code == 200
    assert client.post("/v1/execute", content=body, headers=headers).status_code == 401


def test_assertion_expired(client):
    old = int(time.time()) - 300
    assert execute(client, {"tool": "list_nodes"}, iat=old, exp=old + 60).status_code == 401


def test_assertion_lifetime_too_long(client):
    now = int(time.time())
    assert execute(client, {"tool": "list_nodes"}, iat=now, exp=now + 3600).status_code == 401


@pytest.mark.parametrize(
    "claim,value",
    [
        ("iss", "someone-else"),
        ("aud", "proxmox-mcp"),
        ("aud", ["proxmox-broker", "other"]),
        ("sub", "Alice@Example.com"),
        ("sub", None),
        ("jti", None),
        ("req", None),
    ],
)
def test_assertion_bad_claims(client, claim, value):
    assert execute(client, {"tool": "list_nodes"}, **{claim: value}).status_code == 401


def test_assertion_alg_confusion(client):
    body = json.dumps({"tool": "list_nodes"}).encode()
    now = int(time.time())
    c = {
        "iss": "proxmox-mcp-worker",
        "aud": "proxmox-broker",
        "sub": USER,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        "req": hashlib.sha256(body).hexdigest(),
        "method": "POST",
        "path": "/v1/execute",
    }
    pub_pem = WORKER_KEY.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    tokens = [
        f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(c)}.",
        jwt.encode(c, RSA_KEY, algorithm="RS256"),
        # HMAC with the public key bytes as the secret (classic key confusion)
        _hs256(c, pub_pem),
    ]
    for token in tokens:
        r = client.post(
            "/v1/execute",
            content=body,
            headers={
                "content-type": "application/json",
                "cf-access-jwt-assertion": access_token(),
                "x-mcp-identity": token,
            },
        )
        assert r.status_code == 401


def _hs256(claims: dict, secret: bytes) -> str:
    import hmac

    head = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64(claims)
    sig = hmac.new(secret, f"{head}.{payload}".encode(), hashlib.sha256).digest()
    return f"{head}.{payload}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def test_not_enrolled_user(client, env):
    r = execute(client, {"tool": "list_nodes"}, sub="mallory@example.com")
    assert r.status_code == 403
    assert env["proxmox"].calls == []


def test_vpc_mode_without_access_jwt(env):
    with TestClient(build(require_access=False)) as c:
        assert execute(c, {"tool": "list_nodes"}, access=False).json()["ok"] is True
        assert execute(c, {"tool": "list_nodes"}, ident=False).status_code == 401


# ---- transport hygiene ----------------------------------------------------------


def test_host_mismatch(client):
    r = execute(client, {"tool": "list_nodes"}, headers={"host": "evil.example.com"})
    assert r.status_code == 421


def test_origin_refused(client):
    r = execute(client, {"tool": "list_nodes"}, headers={"origin": "https://evil.example.com"})
    assert r.status_code == 403


def test_oversize_body(client):
    payload = {"tool": "list_nodes", "arguments": {"x": "a" * 5000}}
    assert execute(client, payload).status_code == 413


def test_oversize_chunked_body(env):
    app = build(max_bytes=1024)

    async def run() -> int:
        async def chunks():
            for _ in range(10):
                yield b"x" * 512

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
            r = await c.post("/v1/execute", content=chunks())
            return r.status_code

    import anyio

    assert anyio.run(run) == 413


def test_routes_and_methods(client):
    assert client.get("/v1/execute").status_code == 405
    assert client.get("/v1/execute").headers["allow"] == "POST"
    assert client.post("/v1/catalog").status_code == 405
    assert client.get("/mcp").status_code == 404
    assert client.get("/v1/catalog?x=1").status_code == 404
    assert client.get("/").status_code == 404


def test_rate_limit(env, monkeypatch):
    monkeypatch.setattr(server, "limiter", RateLimiter(2, 100))
    with TestClient(build()) as c:
        assert execute(c, {"tool": "list_nodes"}).json()["ok"] is True
        assert execute(c, {"tool": "list_nodes"}).json()["ok"] is True
        r = execute(c, {"tool": "list_nodes"})
        assert r.json()["ok"] is False and "rate limit" in r.json()["text"]
    assert len(env["proxmox"].calls) == 2


def test_request_rate_limit_429(env, monkeypatch):
    monkeypatch.setenv("MCP_RATE_PER_MIN", "1")  # request limiter = 5x
    with TestClient(build()) as c:
        codes = [catalog(c).status_code for _ in range(6)]
    assert codes[:5] == [200] * 5 and codes[5] == 429


# ---- configuration fails closed -------------------------------------------------


def test_config_refuses_missing_hosts():
    with pytest.raises(ConfigError):
        HttpSettings(allowed_hosts=())


def test_default_hosts_are_loopback_only(monkeypatch):
    monkeypatch.delenv("MCP_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("MCP_PORT", "8765")
    hosts = HttpSettings.from_env().allowed_hosts
    assert "127.0.0.1:8765" in hosts and "localhost:8765" in hosts
    assert all(
        h.split(":")[0] in ("127.0.0.1", "localhost", "[") or h.startswith("[::1]") for h in hosts
    )
    monkeypatch.setenv("MCP_ALLOWED_HOSTS", "broker.internal")
    assert HttpSettings.from_env().allowed_hosts == ("broker.internal",)


def test_identity_assertion_cannot_be_disabled(env, monkeypatch):
    """Even with BROKER_REQUIRE_ACCESS_JWT=0 no env var turns the assertion off."""
    for name in ("BROKER_REQUIRE_IDENTITY_ASSERTION", "BROKER_REQUIRE_ASSERTION", "MCP_INSECURE"):
        monkeypatch.setenv(name, "0")
    monkeypatch.setenv("BROKER_CREDENTIALS_DIR", str(env["audit"].parent))
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(env["audit"].parent))
    settings = HttpSettings(allowed_hosts=("testserver",), require_access_jwt=False)
    with pytest.raises(AssertionConfigError):
        create_app(settings)  # no worker-identity.pub -> refuses to start
    with TestClient(build(require_access=False)) as c:
        r = c.post("/v1/execute", json={"tool": "list_nodes"})
        assert r.status_code == 401


def test_bind_must_be_loopback(monkeypatch):
    monkeypatch.delenv("MCP_ALLOW_NON_LOOPBACK", raising=False)
    check_bind("127.0.0.1")
    check_bind("::1")
    for bind in ("0.0.0.0", "192.0.2.10", "broker.example.com"):
        with pytest.raises(ConfigError):
            check_bind(bind)
    monkeypatch.setenv("MCP_ALLOW_NON_LOOPBACK", "1")
    check_bind("0.0.0.0")


def test_access_jwt_required_needs_config(env, monkeypatch):
    monkeypatch.delenv("CF_ACCESS_TEAM_DOMAIN", raising=False)
    settings = HttpSettings(allowed_hosts=("testserver",))
    with pytest.raises(Exception, match="CF_ACCESS"):
        create_app(settings, assertion_verifier=IdentityAssertionVerifier(WORKER_KEY.public_key()))


def test_missing_worker_key_refuses_to_start(monkeypatch, tmp_path):
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    monkeypatch.setenv("BROKER_CREDENTIALS_DIR", str(tmp_path))
    with pytest.raises(AssertionConfigError):
        IdentityAssertionVerifier.from_credentials()


def test_public_key_must_be_ed25519():
    rsa_pem = RSA_KEY.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(AssertionConfigError):
        load_public_key(rsa_pem)
    ed_pem = WORKER_KEY.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    assert load_public_key(ed_pem.decode())


# ---- units ------------------------------------------------------------------------


def test_replay_cache_window_and_bound():
    t = [0.0]
    cache = ReplayCache(window=120, max_entries=2, clock=lambda: t[0])
    cache.add("jti-0001")
    with pytest.raises(AssertionDenied):
        cache.add("jti-0001")
    cache.add("jti-0002")
    with pytest.raises(AssertionDenied, match="full"):
        cache.add("jti-0003")
    t[0] = 121
    cache.add("jti-0001")  # expired entries are forgotten
    assert len(cache) == 1


def test_rate_limiter_windows():
    t = [0.0]
    rl = RateLimiter(2, 3, clock=lambda: t[0])
    rl.hit("a")
    rl.hit("a")
    with pytest.raises(RateLimited, match="per minute"):
        rl.hit("a")
    rl.hit("b")  # per subject
    t[0] = 61
    rl.hit("a")
    t[0] = 122
    with pytest.raises(RateLimited, match="daily"):
        rl.hit("a")
    t[0] = 26 * 3600
    rl.hit("a")


def test_rate_limiter_bounded_subjects():
    t = [0.0]
    rl = RateLimiter(5, 5, max_subjects=2, clock=lambda: t[0])
    rl.hit("a")
    rl.hit("b")
    with pytest.raises(RateLimited, match="capacity"):
        rl.hit("c")
    t[0] = 26 * 3600
    rl.hit("c")  # idle subjects evicted
    assert len(rl) == 1


async def test_stdio_dynamic_mode_hides_real_tools(env, monkeypatch):
    monkeypatch.setenv("MCP_TOOL_MODE", "dynamic")
    token = server.current_identity.set(Identity(subject="local", kind="local"))
    try:
        result = await server.call_tool("list_nodes", {})
        assert result.isError
        tools = await server.list_tools()
        assert {t.name for t in tools} == {"list_tools", "describe_tool_input", "execute_tool"}
        result = await server.call_tool("execute_tool", {"name": "list_nodes", "arguments": {}})
        assert not result.isError and "pve1" in result.content[0].text
    finally:
        server.current_identity.reset(token)


async def test_errors_never_leak_exception_text(env, monkeypatch):
    class Boom(Exception):
        pass

    async def explode(*a, **k):
        raise Boom("secret=hunter2 at /etc/creds")

    module = server.router.REGISTRY["list_nodes"][1]
    monkeypatch.setattr(module, "handle", explode)
    ok, text = await server.run_tool(
        Identity(subject=USER, kind="user", email=USER), "list_nodes", {}
    )
    assert ok is False and "hunter2" not in text and "internal error" in text


def test_http_app_module_has_no_posix_only_calls():
    import inspect

    src = inspect.getsource(http_app)
    for name in ("os.getuid", "os.geteuid", "fcntl", "pwd.", "grp.", "os.fork"):
        assert name not in src
