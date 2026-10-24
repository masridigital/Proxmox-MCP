"""PROXMOX_READ_ONLY blocks every non-GET request before it reaches the network."""

import httpx
import pytest

from proxmox_mcp import client as client_mod
from proxmox_mcp.credentials import parse_api_token
from proxmox_mcp.identity import Identity


@pytest.fixture
def proxmox(monkeypatch):
    sent: list[str] = []
    audited: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.method)
        return httpx.Response(200, json={"data": None})

    token = parse_api_token("dev@pve!test=00000000-0000-0000-0000-000000000000")
    monkeypatch.setattr(client_mod, "PROXMOX_HOST", "pve.test")
    monkeypatch.setattr(client_mod, "require_identity", lambda: Identity("dev", "local"))
    monkeypatch.setattr(client_mod.ProxmoxClient, "resolve_auth", lambda self, ident: ("rw", token))
    monkeypatch.setattr(client_mod.audit, "audit_event", lambda **f: audited.append(f))
    c = client_mod.ProxmoxClient()
    c.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c, sent, audited


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
async def test_read_only_blocks_writes(monkeypatch, proxmox, method):
    c, sent, audited = proxmox
    monkeypatch.setattr(client_mod, "PROXMOX_READ_ONLY", True)
    with pytest.raises(PermissionError, match="Read-only mode"):
        await c.request(method, "/nodes/pve/qemu/100/status/start")
    assert sent == []
    assert audited[-1]["status"] == "denied"


async def test_read_only_allows_get(monkeypatch, proxmox):
    c, sent, _ = proxmox
    monkeypatch.setattr(client_mod, "PROXMOX_READ_ONLY", True)
    await c.get("/nodes")
    assert sent == ["GET"]


async def test_writes_allowed_for_rw_when_not_read_only(monkeypatch, proxmox):
    c, sent, _ = proxmox
    monkeypatch.setattr(client_mod, "PROXMOX_READ_ONLY", False)
    await c.post("/nodes/pve/qemu/100/status/start")
    assert sent == ["POST"]
