"""The broker against a real TLS endpoint with a pinned self-signed certificate.

No mock transport here: the ProxmoxClient's own TLS-guarded transport connects to
a local HTTPS server. With the right pin the caller's token arrives; with a
wrong pin the connection is dropped after the handshake and the server never
parses a request, so no Authorization header ever leaves the broker.
"""

from __future__ import annotations

from fixtures.broker import USERS, audit_lines, running_broker
from fixtures.tls_proxmox import tls_proxmox


def test_pinned_tls_carries_the_callers_token(tmp_path):
    with tls_proxmox(tmp_path) as pve:
        with running_broker(
            tmp_path / "broker",
            proxmox_host="127.0.0.1",
            proxmox_port=str(pve.port),
            fingerprint=pve.fingerprint,
            mock_transport=False,
        ) as b:
            for mode in ("ro", "operator", "rw"):
                r = b.worker.execute(USERS[mode].email, "list_nodes", {})
                assert r.json()["ok"] is True, r.json()["text"]
    assert pve.requests == [
        ("GET", "/api2/json/nodes", USERS[mode].authorization) for mode in ("ro", "operator", "rw")
    ]


def test_wrong_pin_sends_nothing(tmp_path):
    with tls_proxmox(tmp_path) as pve:
        with running_broker(
            tmp_path / "broker",
            proxmox_host="127.0.0.1",
            proxmox_port=str(pve.port),
            fingerprint="00" * 32,
            mock_transport=False,
        ) as b:
            r = b.worker.execute(USERS["ro"].email, "list_nodes", {})
            body = r.json()
            assert body["ok"] is False
            assert "Proxmox API request failed" in body["text"]
            assert USERS["ro"].secret not in body["text"]
            out = [x for x in audit_lines() if x.get("event") == "proxmox"]
            # httpx surfaces the pin mismatch (TLSVerificationError) as a ConnectError.
            assert [(x["status"], x["error"]) for x in out] == [("error", "ConnectError")]
    assert pve.requests == []
