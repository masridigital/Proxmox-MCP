"""Refused requests and catalog reads reach the hash-chained audit log.

HIPAA 164.308(a)(5)(ii)(C) (log-in monitoring) and SOC 2 CC7.2 need failed
authentication in the tamper-evident log, not only in the service log.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient
from test_h1_http import auth_headers, body_of
from test_http_guard import USER, access_token, assertion, build, env  # noqa: F401

from proxmox_mcp import audit


@pytest.fixture
def client(env):  # noqa: F811
    with TestClient(build(), raise_server_exceptions=False) as c:
        yield c


def _lines() -> list[dict]:
    path = Path(os.environ["MCP_AUDIT_LOG"])
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def _http_lines() -> list[dict]:
    return [x for x in _lines() if x.get("event") in ("http", "catalog")]


def test_missing_auth_is_audited(client):
    r = client.post("/v1/execute", content=b"{}", headers={"content-type": "application/json"})
    assert r.status_code == 401
    (line,) = _http_lines()
    assert line["status"] == "denied" and line["http"] == 401
    assert line["path"] == "/v1/execute" and "deny" in line
    assert audit.verify_chain([os.environ["MCP_AUDIT_LOG"]]) == 0


def test_expired_assertion_is_audited_without_token_material(client):
    body = body_of({"tool": "list_nodes"})
    headers = auth_headers(body)
    old = int(time.time()) - 600
    headers["x-mcp-identity"] = assertion(body, "POST", "/v1/execute", iat=old, exp=old + 60)
    assert client.post("/v1/execute", content=body, headers=headers).status_code == 401
    (line,) = _http_lines()
    assert line["deny"].startswith("identity assertion")
    raw = Path(os.environ["MCP_AUDIT_LOG"]).read_text()
    assert headers["x-mcp-identity"] not in raw and headers["cf-access-jwt-assertion"] not in raw


def test_catalog_read_is_audited_with_user_and_client(client):
    headers = auth_headers(b"", method="GET", path="/v1/catalog")
    headers["cf-connecting-ip"] = "198.51.100.7"
    assert client.get("/v1/catalog", headers=headers).status_code == 200
    (line,) = _http_lines()
    assert line["event"] == "catalog" and line["status"] == "ok"
    assert line["user"] == USER and line["client"] == "198.51.100.7" and line["jti"]


def test_bad_client_ip_header_is_dropped(client):
    headers = {"content-type": "application/json", "cf-connecting-ip": "1.2.3.4\ninjected"}
    client.post("/v1/execute", content=b"{}", headers=headers)
    (line,) = _http_lines()
    assert "client" not in line


def test_unknown_path_is_not_echoed(client):
    assert client.get("/v1/../../etc/passwd").status_code == 404
    (line,) = _http_lines()
    assert line["path"] == "other" and line["http"] == 404


def test_health_ok_is_not_audited(client):
    assert client.get("/healthz").status_code == 200
    assert _http_lines() == []


def test_successful_execute_is_not_double_audited(client):
    body = body_of({"tool": "list_nodes"})
    client.post("/v1/execute", content=body, headers=auth_headers(body))
    assert _http_lines() == []  # server.run_tool writes the tool lines itself
