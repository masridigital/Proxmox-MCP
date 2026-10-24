"""Credentials, per-user token resolution and the request pipeline (offline, MockTransport)."""

import os
import sys
from dataclasses import dataclass
from urllib.parse import parse_qs

import httpx
import pytest

from proxmox_mcp import client as client_mod
from proxmox_mcp import credentials, enrollment
from proxmox_mcp.identity import Identity

SECRET = "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"
ALICE = Identity("alice@example.com", "user", email="alice@example.com", ray_id="ray1")


@dataclass(frozen=True)
class FakeEnrollment:
    subject: str
    mode: str
    proxmox_userid: str
    token_credential: str


@pytest.fixture
def creddir(tmp_path, monkeypatch):
    d = tmp_path / "creds"
    d.mkdir(mode=0o700)
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR", raising=False)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(d))
    return d


def put(d, name, text, mode=0o400):
    p = d / name
    if p.exists():
        os.chmod(p, 0o600)
    p.write_text(text)
    os.chmod(p, mode)
    return p


# --- credentials ---------------------------------------------------------------------


def test_read_strips_one_newline(creddir):
    put(creddir, "pve-token-a", "abc\n")
    assert credentials.read_credential("pve-token-a") == "abc"


def test_dir_precedence_and_fail_closed(tmp_path, monkeypatch, creddir):
    other = tmp_path / "broker"
    other.mkdir()
    put(other, "x", "from-broker")
    put(creddir, "x", "from-systemd")
    monkeypatch.setenv("BROKER_CREDENTIALS_DIR", str(other))
    assert credentials.read_credential("x") == "from-broker"
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR")
    assert credentials.read_credential("x") == "from-systemd"
    monkeypatch.delenv("CREDENTIALS_DIRECTORY")
    with pytest.raises(credentials.CredentialError):
        credentials.read_credential("x")
    monkeypatch.setenv("BROKER_CREDENTIALS_DIR", "relative/dir")
    with pytest.raises(credentials.CredentialError):
        credentials.read_credential("x")


@pytest.mark.parametrize(
    "name", ["../x", "a/b", ".hidden", "", "a..b", "x" * 200, "tok.dpapi", None]
)
def test_bad_names(creddir, name):
    with pytest.raises(credentials.CredentialError):
        credentials.read_credential(name)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX checks")
def test_posix_refusals(creddir):
    put(creddir, "world", "x", mode=0o444)
    with pytest.raises(credentials.CredentialError, match="other users"):
        credentials.read_credential("world")
    put(creddir, "real", "x")
    os.symlink(creddir / "real", creddir / "link")
    with pytest.raises(credentials.CredentialError):
        credentials.read_credential("link")
    with pytest.raises(credentials.CredentialError, match="not found"):
        credentials.read_credential("missing")
    put(creddir, "empty", "\n")
    with pytest.raises(credentials.CredentialError, match="empty"):
        credentials.read_credential("empty")
    put(creddir, "big", "x" * (credentials.MAX_BYTES + 1))
    with pytest.raises(credentials.CredentialError, match="too large"):
        credentials.read_credential("big")


def test_dpapi_dispatch(creddir, tmp_path, monkeypatch):
    put(creddir, "pve-token-a", "plaintext-ignored")
    put(creddir, "pve-token-a.dpapi", "BLOB")
    entropy = tmp_path / "entropy"
    entropy.write_bytes(b"E" * 32)
    os.chmod(entropy, 0o400)
    monkeypatch.setenv("BROKER_DPAPI_ENTROPY_FILE", str(entropy))
    seen = {}

    def fake_unprotect(blob, ent):
        seen["args"] = (blob, ent)
        return b"decrypted\r\n"

    monkeypatch.setattr(credentials, "dpapi_unprotect", fake_unprotect)
    assert credentials.read_credential("pve-token-a") == "decrypted"
    assert seen["args"] == (b"BLOB", b"E" * 32)

    def failing(blob, ent):
        raise OSError("boom")

    monkeypatch.setattr(credentials, "dpapi_unprotect", failing)
    with pytest.raises(credentials.CredentialError, match="could not be decrypted"):
        credentials.read_credential("pve-token-a")


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows behaviour")
def test_dpapi_refused_off_windows(creddir, capsys):
    put(creddir, "t.x", "x")
    put(creddir, "t.x.dpapi", "BLOB")
    with pytest.raises(credentials.CredentialError, match="only supported on Windows"):
        credentials.read_credential("t.x")
    assert credentials.protect_main(["t"]) == 2


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_dpapi_roundtrip_windows():
    blob = credentials.dpapi_protect(b"hello", b"e" * 32)
    assert credentials.dpapi_unprotect(blob, b"e" * 32) == b"hello"


def test_parse_api_token():
    tok = credentials.parse_api_token(
        f"mcp-alice@pve!mcp={SECRET}", expected_userid="mcp-alice@pve"
    )
    assert tok.header() == f"PVEAPIToken=mcp-alice@pve!mcp={SECRET}"
    assert tok.token_id == "mcp-alice@pve!mcp"
    assert SECRET not in repr(tok)
    for bad in ["mcp-alice@pve!mcp", f"mcp-alice!mcp={SECRET}", f"a@pve!mcp={SECRET}\nx", "x" * 10]:
        with pytest.raises(credentials.CredentialError) as ei:
            credentials.parse_api_token(bad)
        assert SECRET not in str(ei.value)
    with pytest.raises(credentials.CredentialError, match="different Proxmox user"):
        credentials.parse_api_token(f"root@pam!mcp={SECRET}", expected_userid="mcp-alice@pve")


# --- request pipeline -------------------------------------------------------------------


@pytest.fixture
def env(monkeypatch, creddir):
    sent: list[httpx.Request] = []
    audited: list[dict] = []
    responses = {"default": lambda r: httpx.Response(200, json={"data": "ok"})}

    def handler(request):
        sent.append(request)
        return responses["default"](request)

    put(creddir, "pve-token-alice", f"mcp-alice@pve!mcp={SECRET}\n")
    table = {
        "alice@example.com": FakeEnrollment(
            "alice@example.com", "operator", "mcp-alice@pve", "pve-token-alice"
        )
    }

    def fake_enrollment_for(identity):
        if identity.kind == "local":
            return FakeEnrollment(identity.subject, "ro", "", "")
        if identity.subject not in table:
            raise PermissionError("not enrolled")
        return table[identity.subject]

    monkeypatch.setattr(enrollment, "enrollment_for", fake_enrollment_for)
    monkeypatch.setattr(client_mod, "PROXMOX_HOST", "pve.example.internal")
    monkeypatch.setattr(client_mod, "PROXMOX_READ_ONLY", False)
    monkeypatch.setattr(client_mod.audit, "audit_event", lambda **f: audited.append(f))
    token = {"ident": ALICE}
    monkeypatch.setattr(client_mod, "require_identity", lambda: token["ident"])
    c = client_mod.ProxmoxClient()
    c.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)

    class Env:
        pass

    e = Env()
    e.c, e.sent, e.audited, e.table, e.responses, e.who = c, sent, audited, table, responses, token
    return e


async def test_per_user_token_and_audit(env):
    assert await env.c.get("/nodes/pve/qemu/100/status/current") == {"data": "ok"}
    req = env.sent[0]
    assert req.headers["Authorization"] == f"PVEAPIToken=mcp-alice@pve!mcp={SECRET}"
    assert str(req.url).startswith("https://pve.example.internal:8006/api2/json/nodes/")
    rec = env.audited[-1]
    assert rec["user"] == "alice@example.com" and rec["token_id"] == "mcp-alice@pve!mcp"
    assert rec["status"] == 200 and rec["mode"] == "operator" and rec["ray"] == "ray1"
    assert all(SECRET not in str(v) for v in rec.values())


async def test_unenrolled_user_denied(env):
    env.who["ident"] = Identity("mallory@example.com", "user")
    with pytest.raises(PermissionError, match="not enrolled"):
        await env.c.get("/nodes")
    assert env.sent == [] and env.audited[-1]["status"] == "denied"


async def test_token_user_must_match_enrollment(env, creddir):
    put(creddir, "pve-token-alice", f"root@pam!mcp={SECRET}")
    with pytest.raises(PermissionError, match="different Proxmox user"):
        await env.c.get("/nodes")
    assert env.sent == []


async def test_token_cache_reloads_on_change(env, creddir):
    await env.c.get("/nodes")
    new = "2b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"
    p = put(creddir, "pve-token-alice", f"mcp-alice@pve!mcp={new}")
    os.utime(p, ns=(1, 1))
    await env.c.get("/nodes")
    assert env.sent[-1].headers["Authorization"].endswith(new)


async def test_outbound_denial_sends_nothing(env):
    with pytest.raises(PermissionError, match="blocked by outbound policy"):
        await env.c.delete("/nodes/pve/qemu/100")  # operator cannot DELETE
    with pytest.raises(PermissionError, match="blocked by outbound policy"):
        await env.c.get("/nodes/../access/users")
    with pytest.raises(PermissionError, match="blocked by outbound policy"):
        await env.c.post("/nodes/pve/qemu/100/agent/exec", {"command": "id"})
    assert env.sent == []
    assert [a["status"] for a in env.audited] == ["denied"] * 3
    assert env.audited[-1]["arg_keys"] == ["command"] and "id" not in env.audited[-1].values()


async def test_phi_write_refused(env):
    env.table["alice@example.com"] = FakeEnrollment(
        "alice@example.com", "rw", "mcp-alice@pve", "pve-token-alice"
    )
    with pytest.raises(PermissionError, match=r"possible PHI detected \(ssn\)"):
        await env.c.put("/nodes/pve/qemu/100/config", {"description": "pt SSN 123-45-6789"})
    assert env.sent == [] and env.audited[-1]["deny"] == "possible PHI detected (ssn)"
    assert "123-45-6789" not in str(env.audited[-1])


async def test_bool_to_int_and_rw_write(env):
    env.table["alice@example.com"] = FakeEnrollment(
        "alice@example.com", "rw", "mcp-alice@pve", "pve-token-alice"
    )
    await env.c.put("/nodes/pve/qemu/100/config", {"onboot": True, "memory": 2048})
    assert parse_qs(env.sent[0].content.decode()) == {"onboot": ["1"], "memory": ["2048"]}


async def test_redirect_not_followed(env):
    env.responses["default"] = lambda r: httpx.Response(
        302, headers={"Location": "https://evil.example.com/"}
    )
    with pytest.raises(httpx.HTTPStatusError):
        await env.c.get("/nodes")
    assert len(env.sent) == 1


async def test_response_size_cap(env):
    env.c.max_response_bytes = 100
    env.responses["default"] = lambda r: httpx.Response(200, content=b"x" * 1000)
    with pytest.raises(ValueError, match="PROXMOX_MAX_RESPONSE_BYTES"):
        await env.c.get("/nodes")
    assert env.audited[-1]["status"] == "error"


async def test_local_identity_uses_env_token_and_local_mode(env, monkeypatch):
    env.who["ident"] = Identity("local", "local")
    monkeypatch.setattr(client_mod, "PROXMOX_USER", "dev@pve")
    monkeypatch.setattr(client_mod, "PROXMOX_TOKEN_NAME", "cli")
    monkeypatch.setattr(client_mod, "PROXMOX_TOKEN_VALUE", SECRET)
    await env.c.get("/nodes")
    assert env.sent[-1].headers["Authorization"] == f"PVEAPIToken=dev@pve!cli={SECRET}"
    with pytest.raises(PermissionError, match="read-only"):
        await env.c.post("/nodes/pve/qemu/100/status/start")  # synthetic enrollment mode ro


async def test_local_identity_without_token_fails_closed(env, monkeypatch):
    env.who["ident"] = Identity("local", "local")
    monkeypatch.setattr(client_mod, "PROXMOX_TOKEN_VALUE", "")
    with pytest.raises(PermissionError):
        await env.c.get("/nodes")
    assert env.sent == []


async def test_no_identity_fails_closed(monkeypatch):
    c = client_mod.ProxmoxClient()
    monkeypatch.setattr(client_mod.audit, "audit_event", lambda **f: None)
    with pytest.raises(PermissionError):
        await c.get("/nodes")


def test_config_validation(monkeypatch):
    monkeypatch.setattr(client_mod, "PROXMOX_HOST", "https://pve/")
    with pytest.raises(ValueError):
        client_mod.validate_config()
    assert client_mod.base_url("fd00::1", "8006") == "https://[fd00::1]:8006/api2/json"
    with pytest.raises(ValueError):
        client_mod.base_url("pve", "99999")
    with pytest.raises(ValueError):
        client_mod.parse_fingerprints("abcd")
    fp = "AB:" * 31 + "AB"
    assert client_mod.parse_fingerprints(f"{fp}, {'cd' * 32}") == (
        bytes([0xAB]) * 32,
        bytes([0xCD]) * 32,
    )
