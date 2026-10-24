"""H3 red team: request encoding, response handling, error/log hygiene, identity binding.

Offline: httpx.MockTransport injected under the client's real httpx.AsyncClient (so
cookie, redirect and decoding behaviour are the production configuration).
"""

import asyncio
import gzip
import json
import logging
import os
import traceback
import zlib
from dataclasses import dataclass
from urllib.parse import parse_qsl

import httpx
import pytest

from proxmox_mcp import audit, credentials, enrollment
from proxmox_mcp import client as client_mod
from proxmox_mcp.identity import Identity, current_identity

SECRET = "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"
SECRET_B = "2c8e7ace-ccfe-4c3e-8c6e-bc9efccef5fe"
ALICE = Identity("alice@example.com", "user", email="alice@example.com", ray_id="ray-a")
BOB = Identity("bob@example.com", "user", email="bob@example.com", ray_id="ray-b")


@dataclass(frozen=True)
class FakeEnrollment:
    subject: str
    mode: str
    proxmox_userid: str
    token_credential: str


def put(d, name, text, mode=0o400):
    p = d / name
    if p.exists():
        os.chmod(p, 0o600)
    p.write_text(text)
    os.chmod(p, mode)
    return p


@pytest.fixture
def creddir(tmp_path, monkeypatch):
    d = tmp_path / "creds"
    d.mkdir(mode=0o700)
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR", raising=False)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(d))
    return d


@pytest.fixture
def env(monkeypatch, creddir, tmp_path):
    sent: list[httpx.Request] = []
    responses = {"default": lambda r: httpx.Response(200, json={"data": "ok"})}

    async def handler(request):
        await request.aread()
        sent.append(request)
        result = responses["default"](request)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    put(creddir, "pve-token-alice", f"mcp-alice@pve!mcp={SECRET}\n")
    put(creddir, "pve-token-bob", f"mcp-bob@pve!mcp={SECRET_B}\n")
    table = {
        "alice@example.com": FakeEnrollment(
            "alice@example.com", "rw", "mcp-alice@pve", "pve-token-alice"
        ),
        "bob@example.com": FakeEnrollment("bob@example.com", "rw", "mcp-bob@pve", "pve-token-bob"),
    }

    def fake_enrollment_for(identity):
        if identity.subject not in table:
            raise PermissionError("not enrolled")
        return table[identity.subject]

    monkeypatch.setattr(enrollment, "enrollment_for", fake_enrollment_for)
    monkeypatch.setattr(client_mod, "PROXMOX_HOST", "pve.example.internal")
    monkeypatch.setattr(client_mod, "PROXMOX_READ_ONLY", False)
    # Real audit sink (conftest points MCP_AUDIT_LOG at tmp) so lines can be inspected.
    audit.reset_for_tests()
    c = client_mod.ProxmoxClient(transport=httpx.MockTransport(handler))
    tok = current_identity.set(ALICE)

    class Env:
        pass

    e = Env()
    e.c, e.sent, e.table, e.responses = c, sent, table, responses
    e.audit_path = os.environ["MCP_AUDIT_LOG"]
    yield e
    current_identity.reset(tok)
    audit.reset_for_tests()


def audit_text(e) -> str:
    with open(e.audit_path, encoding="utf-8") as f:
        return f.read()


# --- query-string / form-body injection -------------------------------------------------


async def test_query_values_cannot_inject_parameters(env):
    evil = "a&full=1&delete=all#frag?x=%0d%0aX-Injected: 1"
    await env.c.get("/cluster/resources", {"type": evil})
    req = env.sent[0]
    assert req.url.params.multi_items() == [("type", evil)]
    assert req.url.path == "/api2/json/cluster/resources" and not req.url.fragment
    assert "X-Injected" not in req.headers
    with pytest.raises(PermissionError, match="invalid request parameter type"):
        await env.c.get("/cluster/resources", {"type": "vm\r\nX-Injected: 1"})
    assert len(env.sent) == 1


@pytest.mark.parametrize(
    "key", ["x=y", "a&b", "a b", "a\nb", "", "k" * 65, "näme", 1, None, ("a",), "-x", "_csrf"]
)
async def test_invalid_parameter_names_refused(env, key):
    with pytest.raises(PermissionError, match="invalid request parameter"):
        await env.c.put("/nodes/pve/qemu/100/config", {key: "1"})
    assert env.sent == []


@pytest.mark.parametrize(
    "value",
    [
        {"nested": "dict"},
        [{"a": 1}],
        [["x"]],
        object(),
        b"bytes",
        float("nan"),
        float("inf"),
        "a\x00b",
        "a\x1bb",
    ],
)
async def test_unencodable_values_refused(env, value):
    with pytest.raises(PermissionError, match="invalid request parameter memory"):
        await env.c.put("/nodes/pve/qemu/100/config", {"memory": value})
    assert env.sent == []
    assert "denied" in audit_text(env)


async def test_crlf_only_in_free_text_fields(env):
    with pytest.raises(PermissionError, match="invalid request parameter net0"):
        await env.c.put(
            "/nodes/pve/qemu/100/config", {"net0": "virtio,bridge=vmbr0\nhostpci0: 01:00"}
        )
    assert env.sent == []
    await env.c.put("/nodes/pve/qemu/100/config", {"description": "line one\r\nline two"})
    assert dict(parse_qsl(env.sent[-1].content.decode())) == {"description": "line one\r\nline two"}


async def test_form_body_encoding(env):
    await env.c.put(
        "/nodes/pve/qemu/100/config",
        {
            "onboot": True,
            "protection": False,
            "memory": 2048,
            "cpulimit": 0.5,
            "description": "a&b=c d+e%",
            "delete": None,
            "tags": ["a", "b"],
        },
    )
    req = env.sent[-1]
    assert req.headers["Content-Type"] == "application/x-www-form-urlencoded"
    pairs = parse_qsl(req.content.decode(), keep_blank_values=True)
    assert pairs == [
        ("onboot", "1"),
        ("protection", "0"),
        ("memory", "2048"),
        ("cpulimit", "0.5"),
        ("description", "a&b=c d+e%"),
        ("tags", "a"),
        ("tags", "b"),
    ]  # None means "not set": dropped, never sent as an empty (clearing) value


async def test_get_bool_params_and_none(env):
    await env.c.get("/cluster/resources", {"full": True, "type": None})
    assert env.sent[-1].url.params.multi_items() == [("full", "1")]


async def test_non_dict_data_refused(env):
    with pytest.raises(PermissionError, match="invalid request parameter"):
        await env.c.put("/nodes/pve/qemu/100/config", [("memory", "1")])
    with pytest.raises(PermissionError, match="invalid request parameter"):
        await env.c.put("/nodes/pve/qemu/100/config", "memory=1&onboot=1")
    assert env.sent == []


async def test_oversized_body_refused(env):
    with pytest.raises(PermissionError, match="too large"):
        await env.c.put("/nodes/pve/qemu/100/config", {"description": "x" * (2 * 1024 * 1024)})
    assert env.sent == []


@pytest.mark.parametrize("method", ["poſt", "PoSt\n", "GET ", b"GET", None])
async def test_client_method_normalisation_is_ascii_only(env, method):
    with pytest.raises(PermissionError):
        await env.c.request(method, "/nodes/pve/qemu/100/status/start")
    assert env.sent == []


# --- headers --------------------------------------------------------------------------------


async def test_request_headers_are_fixed(env):
    await env.c.get("/nodes")
    h = env.sent[0].headers
    assert h["Host"] == "pve.example.internal:8006"
    assert h["Accept-Encoding"] == "identity"
    assert "Cookie" not in h and "Proxy-Authorization" not in h
    assert h["Authorization"] == f"PVEAPIToken=mcp-alice@pve!mcp={SECRET}"


async def test_cookies_never_persist_across_requests_or_users(env):
    env.responses["default"] = lambda r: httpx.Response(
        200, json={"data": 1}, headers={"Set-Cookie": "PVEAuthCookie=stolen; Path=/"}
    )
    await env.c.get("/nodes")
    current_identity.set(BOB)
    await env.c.get("/nodes")
    assert "Cookie" not in env.sent[1].headers
    assert len(env.c.client.cookies) == 0


# --- response handling -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "encoding", ["gzip", "deflate", "br", "zstd", "gzip, gzip", "x-gzip", "compress"]
)
async def test_compressed_responses_refused_without_decoding(env, encoding):
    bomb = (
        gzip.compress(b"\0" * (8 * 1024 * 1024))
        if "gzip" in encoding
        else zlib.compress(b"\0" * 1024)
    )
    pulled = []

    async def body():
        pulled.append(1)
        yield bomb

    stream = _Stream().init(body)
    env.responses["default"] = lambda r: httpx.Response(
        200,
        stream=stream,
        headers={"Content-Encoding": encoding, "Content-Type": "application/json"},
    )
    with pytest.raises(ValueError, match="Content-Encoding"):
        await env.c.get("/nodes")
    assert pulled == [] and stream.closed  # refused on the header, nothing read or decoded


async def test_identity_encoding_accepted(env):
    env.responses["default"] = lambda r: httpx.Response(
        200, content=b'{"data":1}', headers={"Content-Encoding": "identity"}
    )
    assert await env.c.get("/nodes") == {"data": 1}


async def test_content_length_over_cap_refused_before_reading(env):
    env.c.max_response_bytes = 100
    read = []

    async def body():
        read.append(1)
        yield b"x" * 10

    env.responses["default"] = lambda r: httpx.Response(
        200, headers={"Content-Length": "999999999"}, stream=_Stream().init(body)
    )
    with pytest.raises(ValueError, match="PROXMOX_MAX_RESPONSE_BYTES"):
        await env.c.get("/nodes")
    assert read == []


class _Stream(httpx.AsyncByteStream):
    def init(self, gen):
        self._gen = gen
        self.closed = False
        return self

    async def __aiter__(self):
        async for chunk in self._gen():
            yield chunk

    async def aclose(self):
        self.closed = True


async def test_chunked_infinite_response_is_capped(env):
    env.c.max_response_bytes = 1024 * 1024
    produced = []

    async def forever():
        while True:
            produced.append(65536)
            yield b"x" * 65536

    stream = _Stream().init(forever)
    env.responses["default"] = lambda r: httpx.Response(
        200, headers={"Transfer-Encoding": "chunked"}, stream=stream
    )
    with pytest.raises(ValueError, match="PROXMOX_MAX_RESPONSE_BYTES"):
        await env.c.get("/nodes")
    assert sum(produced) <= 1024 * 1024 + 65536
    assert stream.closed


async def test_slowloris_response_hits_total_deadline(env):
    env.c.total_timeout = 0.5

    async def trickle():
        yield b'{"data":'
        while True:
            await asyncio.sleep(0.1)  # each read is well inside the per-read timeout
            yield b" "

    env.responses["default"] = lambda r: httpx.Response(200, stream=_Stream().init(trickle))
    loop = asyncio.get_running_loop()
    started = loop.time()
    with pytest.raises(httpx.TimeoutException, match="PROXMOX_TOTAL_TIMEOUT"):
        await env.c.get("/nodes")
    assert loop.time() - started < 3
    assert '"status": "error"' in audit_text(env) or '"status":"error"' in audit_text(env)


async def test_redirect_to_other_host_is_error_and_single_request(env):
    env.responses["default"] = lambda r: httpx.Response(
        307, headers={"Location": "https://evil.example.com/steal"}
    )
    with pytest.raises(httpx.HTTPStatusError) as ei:
        await env.c.get("/nodes")
    assert len(env.sent) == 1
    assert "evil.example.com" not in str(ei.value)


# --- secret hygiene: exceptions, tracebacks, logs, audit -------------------------------------


def _walk_exception(exc):
    seen = set()
    stack = [exc]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        stack += [e.__cause__, e.__context__]


def _assert_no_secret_reachable(exc, secret=SECRET):
    for e in _walk_exception(exc):
        assert secret not in str(e) and secret not in repr(e)
        assert secret not in "".join(traceback.format_exception(e))
        for attr in ("request", "response"):
            try:
                obj = getattr(e, attr)
            except Exception:  # noqa: S112 - httpx raises RuntimeError when unset
                continue
            if attr == "response":
                obj = obj.request
            assert "authorization" not in {k.lower() for k in obj.headers}
        tb = e.__traceback__
        while tb is not None:
            for value in tb.tb_frame.f_locals.values():
                assert secret not in repr(value)
                if isinstance(value, httpx.Request | httpx.Response):
                    req = value if isinstance(value, httpx.Request) else value.request
                    assert "authorization" not in {k.lower() for k in req.headers}
            tb = tb.tb_next


@pytest.mark.parametrize(
    "exc_type", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError, httpx.ReadError]
)
async def test_transport_errors_carry_no_token(env, exc_type):
    def boom(request):
        raise exc_type(
            f"failed talking to {request.url} with {request.headers['Authorization']}",
            request=request,
        )

    env.responses["default"] = boom
    with pytest.raises(httpx.TransportError) as ei:
        await env.c.get("/nodes", {"marker": "QSMARKER"})
    _assert_no_secret_reachable(ei.value)
    assert "QSMARKER" not in str(ei.value)


async def test_status_error_carries_no_token(env):
    env.responses["default"] = lambda r: httpx.Response(
        401, json={"message": f"authentication failure for PVEAPIToken=mcp-alice@pve!mcp={SECRET}"}
    )
    with pytest.raises(httpx.HTTPStatusError) as ei:
        await env.c.get("/nodes", {"marker": "QSMARKER"})
    _assert_no_secret_reachable(ei.value)
    assert ei.value.response.status_code == 401
    assert "QSMARKER" not in str(ei.value)


async def test_cap_and_json_errors_carry_no_token(env):
    env.c.max_response_bytes = 10
    env.responses["default"] = lambda r: httpx.Response(200, content=b"y" * 100)
    with pytest.raises(ValueError) as ei:
        await env.c.get("/nodes")
    _assert_no_secret_reachable(ei.value)
    env.c.max_response_bytes = 1000
    env.responses["default"] = lambda r: httpx.Response(200, content=b"not json")
    with pytest.raises(ValueError) as ei:
        await env.c.get("/nodes")
    _assert_no_secret_reachable(ei.value)


async def test_no_token_or_query_values_in_any_log_record_or_audit_line(env, caplog):
    root = logging.getLogger()
    old = root.level
    root.setLevel(logging.DEBUG)
    try:
        with caplog.at_level(logging.DEBUG):
            await env.c.get("/nodes", {"marker": "QSMARKER"})
            env.responses["default"] = lambda r: httpx.Response(500, text="boom")
            with pytest.raises(httpx.HTTPStatusError):
                await env.c.get("/nodes")
            with pytest.raises(PermissionError):
                await env.c.get("/access/ticket")
            put_err = None
            try:
                await env.c.put("/nodes/pve/qemu/100/config", {"memory": {"x": SECRET}})
            except PermissionError as exc:
                put_err = exc
            assert put_err is not None and SECRET not in str(put_err)
    finally:
        root.setLevel(old)
    text = "\n".join(f"{r.name} {r.getMessage()} {r.args!r}" for r in caplog.records)
    assert SECRET not in text and "PVEAPIToken" not in text
    assert "QSMARKER" not in text
    lines = audit_text(env)
    assert SECRET not in lines and "PVEAPIToken" not in lines and "QSMARKER" not in lines
    assert "mcp-alice@pve!mcp" in lines  # token id (not secret) is attributed


# --- identity binding ----------------------------------------------------------------------


async def test_concurrent_users_get_their_own_tokens(env):
    async def call(ident, n):
        current_identity.set(ident)
        for _ in range(n):
            await env.c.get("/nodes")
            await asyncio.sleep(0)

    await asyncio.gather(*(call(ALICE if i % 2 else BOB, 5) for i in range(8)))
    assert len(env.sent) == 40
    users = [r.headers["Authorization"] for r in env.sent]
    assert all(u.endswith(SECRET) or u.endswith(SECRET_B) for u in users)
    lines = [
        json.loads(x)
        for x in audit_text(env).splitlines()
        if '"kind": "proxmox"' in x or '"kind":"proxmox"' in x
    ]
    for line in lines:
        expect = "mcp-alice@pve!mcp" if line["user"] == "alice@example.com" else "mcp-bob@pve!mcp"
        assert line["token_id"] == expect


async def test_shared_credential_between_two_subjects_is_refused(env):
    # Misconfiguration: bob's enrollment points at alice's token file and user.
    env.table["bob@example.com"] = FakeEnrollment(
        "bob@example.com", "rw", "mcp-alice@pve", "pve-token-alice"
    )
    await env.c.get("/nodes")  # alice binds her credential
    current_identity.set(BOB)
    with pytest.raises(PermissionError, match="bound to another"):
        await env.c.get("/nodes")
    assert len(env.sent) == 1


async def test_token_user_mismatch_for_other_identity(env, creddir):
    env.table["bob@example.com"] = FakeEnrollment(
        "bob@example.com", "rw", "mcp-bob@pve", "pve-token-alice"
    )
    current_identity.set(BOB)
    with pytest.raises(PermissionError, match="different Proxmox user"):
        await env.c.get("/nodes")
    assert env.sent == []


# --- credential cache TOCTOU -----------------------------------------------------------------


async def test_cache_cannot_be_poisoned_by_swap_during_read(env, creddir, monkeypatch):
    real_read = credentials._read_file
    path = creddir / "pve-token-alice"
    evil = creddir / "evil"
    put(creddir, "evil", f"mcp-alice@pve!mcp={SECRET_B}")
    parked = creddir / "parked"
    state = {"armed": True}

    def swapping_read(name, p):
        if state["armed"] and name == "pve-token-alice":
            state["armed"] = False
            os.replace(path, parked)
            os.replace(evil, path)  # attacker content at the name for the read only
            try:
                return real_read(name, p)
            finally:
                os.replace(path, evil)
                os.replace(parked, path)  # original inode back, mtime untouched
        return real_read(name, p)

    monkeypatch.setattr(credentials, "_read_file", swapping_read)
    await env.c.get("/nodes")  # read raced: whichever file was read is used once
    await env.c.get("/nodes")
    # The cache entry must describe the file actually read, so the restored file is re-read.
    assert env.sent[-1].headers["Authorization"].endswith(SECRET)
