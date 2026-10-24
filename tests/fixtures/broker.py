"""End-to-end harness: the real broker ASGI app, driven exactly as the Worker drives it.

What is real: transport/http_app.create_app (size cap, Host check, Access service
token JWT, Ed25519 identity assertion with body/method/path binding and replay
cache, enrollment, rate limits), server.run_tool, policy, router validation,
the ProxmoxClient (per-user token resolution from credential files, outbound
policy, PHI write check), output rendering and the hash-chained audit log.

What is fake: the Cloudflare Access JWKS (a locally generated RSA key served by
an httpx.MockTransport) and the Proxmox API (MockProxmox, installed in place of
the client's TLS-guarded transport; test_e2e_tls.py covers the real transport
against a local TLS server with a pinned self-signed certificate).

The temp credentials directory holds what the Windows broker holds in
C:\\ProgramData\\ProxmoxMCP\\credentials: enrollment.json, one pve-token-<user>
file per enrolled person, and worker-identity.pub. Files are 0400.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jwt.algorithms import RSAAlgorithm
from starlette.testclient import TestClient

from proxmox_mcp import audit, server
from proxmox_mcp import client as client_mod
from proxmox_mcp.transport.access_jwt import AccessVerifier
from proxmox_mcp.transport.http_app import HttpSettings, create_app
from proxmox_mcp.transport.ratelimit import RateLimiter

from .mock_proxmox import MockProxmox

TEAM = "https://example-team.cloudflareaccess.com"
BROKER_AUD = "a" * 64
SERVICE_CLIENT_ID = "0123456789abcdef0123456789abcdef.access"
BROKER_HOST = "broker.example.com"
RAY = "8f0000000000abcd-IAD"
MODES = ("ro", "operator", "rw")


@dataclass(frozen=True)
class User:
    mode: str
    email: str
    proxmox_userid: str
    credential: str
    secret: str

    @property
    def token_id(self) -> str:
        return f"{self.proxmox_userid}!mcp"

    @property
    def authorization(self) -> str:
        return f"PVEAPIToken={self.token_id}={self.secret}"


USERS: dict[str, User] = {
    mode: User(
        mode=mode,
        email=f"{mode}.user@example.com",
        proxmox_userid=f"mcp-{mode}@pve",
        credential=f"pve-token-{mode}",
        secret=str(uuid.uuid4()),
    )
    for mode in MODES
}
UNENROLLED = "mallory@example.com"


def _write_0400(path: Path, text: str) -> None:
    path.write_text(text)
    os.chmod(path, 0o400)


@dataclass
class Keys:
    access_rsa: rsa.RSAPrivateKey = field(
        default_factory=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    )
    worker: ed25519.Ed25519PrivateKey = field(default_factory=ed25519.Ed25519PrivateKey.generate)

    def jwks(self) -> dict[str, Any]:
        jwk = json.loads(RSAAlgorithm.to_jwk(self.access_rsa.public_key()))
        jwk.update({"kid": "e2e-1", "alg": "RS256", "use": "sig"})
        return {"keys": [jwk]}

    def worker_public_pem(self) -> str:
        return (
            self.worker.public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )


def write_credentials(directory: Path, keys: Keys) -> None:
    users = {
        u.email: {
            "mode": u.mode,
            "proxmox_userid": u.proxmox_userid,
            "token_credential": u.credential,
        }
        for u in USERS.values()
    }
    _write_0400(directory / "enrollment.json", json.dumps({"users": users}, indent=1))
    for u in USERS.values():
        _write_0400(directory / u.credential, f"{u.token_id}={u.secret}\n")
    _write_0400(directory / "worker-identity.pub", keys.worker_public_pem())


class Worker:
    """Signs requests the way the Cloudflare Worker does and calls the broker."""

    def __init__(self, http: TestClient, keys: Keys) -> None:
        self.http = http
        self.keys = keys

    def access_token(self) -> str:
        now = int(time.time())
        claims = {
            "aud": [BROKER_AUD],
            "common_name": SERVICE_CLIENT_ID,
            "sub": "",
            "iss": TEAM,
            "iat": now,
            "nbf": now,
            "exp": now + 600,
            "type": "app",
        }
        return jwt.encode(claims, self.keys.access_rsa, algorithm="RS256", headers={"kid": "e2e-1"})

    def assertion(self, email: str, body: bytes, method: str, path: str) -> str:
        now = int(time.time())
        claims = {
            "iss": "proxmox-mcp-worker",
            "aud": "proxmox-broker",
            "sub": email,
            "iat": now,
            "exp": now + 60,
            "jti": str(uuid.uuid4()),
            "ray": RAY,
            "req": hashlib.sha256(body).hexdigest(),
            "method": method,
            "path": path,
        }
        return jwt.encode(claims, self.keys.worker, algorithm="EdDSA")

    def _headers(self, email: str, body: bytes, method: str, path: str) -> dict[str, str]:
        return {
            "host": BROKER_HOST,
            "cf-ray": RAY,
            "cf-access-jwt-assertion": self.access_token(),
            "x-mcp-identity": self.assertion(email, body, method, path),
        }

    def catalog(self, email: str) -> httpx.Response:
        return self.http.get("/v1/catalog", headers=self._headers(email, b"", "GET", "/v1/catalog"))

    def execute(self, email: str, tool: str, arguments: dict[str, Any]) -> httpx.Response:
        body = json.dumps({"tool": tool, "arguments": arguments}).encode()
        headers = self._headers(email, body, "POST", "/v1/execute")
        headers["content-type"] = "application/json"
        return self.http.post("/v1/execute", content=body, headers=headers)


@dataclass
class Broker:
    worker: Worker
    proxmox: MockProxmox
    credentials: Path


@contextlib.contextmanager
def running_broker(
    tmp_dir: Path,
    *,
    admin_tools: bool = True,
    proxmox_host: str = "pve.example.internal",
    proxmox_port: str = "8006",
    fingerprint: str = "ab" * 32,
    mock_transport: bool = True,
) -> Iterator[Broker]:
    """Start the broker with a temp credentials dir. Restores all state on exit.

    mock_transport=True puts MockProxmox in place of the TLS-guarded transport;
    False keeps the real transport (pinned TLS to proxmox_host:proxmox_port).
    """
    keys = Keys()
    creds = tmp_dir / "credentials"
    creds.mkdir(mode=0o700, parents=True)
    write_credentials(creds, keys)
    proxmox = MockProxmox()
    jwks = keys.jwks()

    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("CREDENTIALS_DIRECTORY", str(creds))
        # A module-scoped broker starts before the per-test audit path is set.
        mp.setenv("MCP_AUDIT_LOG", str(tmp_dir / "audit" / "audit.jsonl"))
        for var in (
            "BROKER_CREDENTIALS_DIR",
            "MCP_ENROLLMENT_FILE",
            "MCP_TOOL_ALLOW",
            "MCP_TOOL_DENY",
            "MCP_PHI_CONTACT",
        ):
            mp.delenv(var, raising=False)
        mp.setenv("MCP_ALLOW_ADMIN_TOOLS", "1" if admin_tools else "0")
        mp.setenv("MCP_RATE_PER_MIN", "1000000")
        mp.setenv("MCP_RATE_PER_DAY", "100000000")
        mp.setattr(server, "limiter", RateLimiter(1_000_000, 100_000_000))
        mp.setattr(server, "proxmox", None)
        mp.setattr(client_mod, "PROXMOX_HOST", proxmox_host)
        mp.setattr(client_mod, "PROXMOX_PORT", proxmox_port)
        mp.setattr(client_mod, "PROXMOX_READ_ONLY", False)
        mp.setattr(client_mod, "PROXMOX_INSECURE_TLS", False)
        mp.setattr(client_mod, "PROXMOX_CA_BUNDLE", "")
        mp.setattr(client_mod, "PROXMOX_TLS_FINGERPRINT", fingerprint)
        if mock_transport:
            mp.setattr(
                client_mod, "GuardedTransport", lambda ssl_context, pins: proxmox.transport()
            )
        settings = HttpSettings(allowed_hosts=(BROKER_HOST,), require_access_jwt=True)
        access = AccessVerifier(
            TEAM,
            BROKER_AUD,
            service_client_ids=[SERVICE_CLIENT_ID],
            http_client=httpx.AsyncClient(
                transport=httpx.MockTransport(lambda request: httpx.Response(200, json=jwks))
            ),
        )
        # assertion_verifier is not injected: the broker loads worker-identity.pub
        # from the credentials directory, as in production.
        app = create_app(settings, access_verifier=access)
        audit.reset_for_tests()
        try:
            with TestClient(
                app, base_url=f"http://{BROKER_HOST}", raise_server_exceptions=False
            ) as http:
                yield Broker(worker=Worker(http, keys), proxmox=proxmox, credentials=creds)
        finally:
            audit.reset_for_tests()


def audit_lines(path: str | os.PathLike | None = None) -> list[dict[str, Any]]:
    p = Path(path or audit.configured_path())
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]
