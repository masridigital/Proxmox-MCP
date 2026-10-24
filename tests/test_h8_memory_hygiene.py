"""H8: token material never appears in repr/str of clients, credentials, exceptions or logs.

Python cannot securely zero a str (see config.py "Memory hygiene"); what it can do
is keep the token out of every textual rendering and every long-lived object.
Two strict xfails mark gaps closed by patches C3 and CR1 in the H8 patch list;
remove the marker when the patch is applied.
"""

import logging
import os
import pickle
from dataclasses import dataclass

import httpx
import pytest

from proxmox_mcp import client as client_mod
from proxmox_mcp import credentials, enrollment
from proxmox_mcp.identity import Identity

SECRET = "7f3e9a10-5b2c-4d8e-9f01-23456789abcd"
ALICE = Identity("alice@example.com", "user", email="alice@example.com", ray_id="ray1")


@dataclass(frozen=True)
class FakeEnrollment:
    subject: str
    mode: str
    proxmox_userid: str
    token_credential: str


def no_secret(*objs):
    for obj in objs:
        for text in (repr(obj), str(obj), f"{obj!r}", f"{obj}"):
            assert SECRET not in text, text
            assert SECRET.replace("-", "") not in text


@pytest.fixture
def env(tmp_path, monkeypatch):
    d = tmp_path / "creds"
    d.mkdir(mode=0o700)
    p = d / "pve-token-alice"
    p.write_text(f"mcp-alice@pve!mcp={SECRET}\n")
    os.chmod(p, 0o400)
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR", raising=False)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(d))
    table = {
        "alice@example.com": FakeEnrollment(
            "alice@example.com", "operator", "mcp-alice@pve", "pve-token-alice"
        )
    }

    def fake_enrollment_for(identity):
        if identity.subject not in table:
            raise PermissionError("not enrolled")
        return table[identity.subject]

    audited: list[dict] = []
    responses = {"fn": lambda r: httpx.Response(200, json={"data": "ok"})}
    monkeypatch.setattr(enrollment, "enrollment_for", fake_enrollment_for)
    monkeypatch.setattr(client_mod, "PROXMOX_HOST", "pve.example.internal")
    monkeypatch.setattr(client_mod, "PROXMOX_READ_ONLY", False)
    monkeypatch.setattr(client_mod.audit, "audit_event", lambda **f: audited.append(f))
    monkeypatch.setattr(client_mod, "require_identity", lambda: ALICE)
    c = client_mod.ProxmoxClient()
    c.client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: responses["fn"](r)), follow_redirects=False
    )
    return c, audited, responses


async def test_client_and_cache_never_render_token(env, caplog):
    c, audited, _ = env
    with caplog.at_level(logging.DEBUG):
        assert await c.get("/nodes/pve/qemu/100/status/current") == {"data": "ok"}
    no_secret(c, c._token_cache, vars(c), audited)
    ((_, token),) = c._token_cache.values()
    no_secret(token)
    assert all(SECRET not in r.getMessage() for r in caplog.records)
    assert all(SECRET not in str(r.args) for r in caplog.records)


async def test_http_error_never_renders_token(env, caplog):
    c, audited, responses = env
    responses["fn"] = lambda r: httpx.Response(401, json={"message": "authentication failure"})
    with caplog.at_level(logging.DEBUG), pytest.raises(httpx.HTTPStatusError) as ei:
        await c.get("/nodes")
    no_secret(ei.value, ei.value.args, ei.value.request, ei.value.response, audited)
    assert all(SECRET not in r.getMessage() for r in caplog.records)


async def test_transport_error_never_renders_token(env):
    c, audited, responses = env

    def fail(request):
        raise httpx.ConnectError("connection refused", request=request)

    responses["fn"] = fail
    with pytest.raises(httpx.ConnectError) as ei:
        await c.get("/nodes")
    no_secret(ei.value, ei.value.args, audited)


async def test_policy_denial_never_renders_token(env):
    c, audited, _ = env
    with pytest.raises(PermissionError) as ei:
        await c.delete("/access/users/x/token/y")
    no_secret(ei.value, audited)


def test_credential_errors_never_render_content(tmp_path, monkeypatch):
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(tmp_path))
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR", raising=False)
    bad = tmp_path / "bad"
    bad.write_text(f"garbage {SECRET}")
    os.chmod(bad, 0o444)  # "other" readable: refused, and the message names the file only
    for call in (
        lambda: credentials.read_credential("bad"),
        lambda: credentials.parse_api_token(f"garbage {SECRET}"),
        lambda: credentials.parse_api_token(f"x@pve!t={SECRET}", expected_userid="y@pve"),
    ):
        with pytest.raises(credentials.CredentialError) as ei:
            call()
        no_secret(ei.value, ei.value.args)


def test_api_token_renderings():
    tok = credentials.parse_api_token(f"mcp-alice@pve!mcp={SECRET}")
    no_secret(tok, [tok], {"t": tok}, (tok,))
    assert tok.token_id == "mcp-alice@pve!mcp"


async def test_request_object_does_not_retain_token(env):
    c, _, responses = env
    responses["fn"] = lambda r: httpx.Response(500, json={"message": "boom"})
    with pytest.raises(httpx.HTTPStatusError) as ei:
        await c.get("/nodes")
    # The exception keeps the request alive (tracebacks, error reporters, debuggers).
    assert "Authorization" not in ei.value.request.headers


def test_api_token_cannot_be_pickled():
    tok = credentials.parse_api_token(f"mcp-alice@pve!mcp={SECRET}")
    with pytest.raises(TypeError):
        pickle.dumps(tok)
