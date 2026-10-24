"""Cross-implementation check: the broker accepts the Worker's X-MCP-Identity bytes.

worker/test/fixtures/assertion-vector.json is a TEST-ONLY Ed25519 key pair and a
compact JWS produced by the TypeScript Worker (WebCrypto). The broker's Python
verifier must accept exactly those bytes for the vector body, method and path,
and refuse them for anything else. Skipped when the worker/ project is not in
this checkout.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import jwt.api_jwt
import pytest

from proxmox_mcp.transport.identity_assertion import (
    AssertionDenied,
    IdentityAssertionVerifier,
    load_public_key,
)

VECTOR = (
    Path(__file__).resolve().parents[1] / "worker" / "test" / "fixtures" / "assertion-vector.json"
)

pytestmark = pytest.mark.skipif(not VECTOR.exists(), reason="worker/ project not in this checkout")


@pytest.fixture
def vector(monkeypatch):
    doc = json.loads(VECTOR.read_text())
    at = float(doc["verify_at_unix"])

    class FrozenDatetime(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return dt.datetime.fromtimestamp(at, tz)

    monkeypatch.setattr(jwt.api_jwt, "datetime", FrozenDatetime)
    verifier = IdentityAssertionVerifier(
        load_public_key(doc["public_key_spki_pem"]), now=lambda: at
    )
    return doc, verifier


def test_broker_accepts_worker_signed_assertion(vector):
    doc, verifier = vector
    verified = verifier.verify(
        doc["jws"], body=doc["body"].encode(), method="POST", path="/v1/execute"
    )
    assert verified.identity.subject == doc["claims"]["sub"]
    assert verified.identity.ray_id == doc["claims"]["ray"]
    assert verified.jti == doc["claims"]["jti"]


@pytest.mark.parametrize(
    "body,method,path",
    [
        ('{"tool":"get_node_status","arguments":{"node":"pve2"}}', "POST", "/v1/execute"),
        (None, "GET", "/v1/execute"),
        (None, "POST", "/v1/catalog"),
    ],
)
def test_worker_assertion_is_bound_to_body_method_and_path(vector, body, method, path):
    doc, verifier = vector
    with pytest.raises(AssertionDenied):
        verifier.verify(doc["jws"], body=(body or doc["body"]).encode(), method=method, path=path)
