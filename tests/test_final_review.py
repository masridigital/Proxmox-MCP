"""Regression tests for the confirmed findings of the final independent security review.

1. A read-only user could freeze the broker (redaction ran on the event loop).
2. Inbound tool audit lines carried an unkeyed sha256 of the arguments (PHI recoverable).
4. A request abandoned before its body was audited as status "ok".
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import secrets
import string
import threading
import time

from fixtures import broker as broker_fx
from fixtures import mock_proxmox
from fixtures.broker import BROKER_HOST, USERS, audit_lines, running_broker
from fixtures.tool_args import UPID


def _big_log(n: int = 50000) -> list[dict]:
    rnd = random.Random(1)  # noqa: S311 - test data
    alphabet = string.ascii_letters + string.digits + " :-/."
    return [{"n": i, "t": "".join(rnd.choice(alphabet) for _ in range(120))} for i in range(n)]


def test_large_read_does_not_freeze_the_broker(tmp_path, monkeypatch):
    log = _big_log()
    orig = mock_proxmox.response_for

    def resp(method, path):
        return {"data": log} if path.endswith("/log") else orig(method, path)

    monkeypatch.setattr(mock_proxmox, "response_for", resp)
    with running_broker(tmp_path) as b:
        done: dict = {}

        def attack():
            r = b.worker.execute(
                USERS["ro"].email, "get_task_log", {"node": "pve1", "upid": UPID, "limit": 50000}
            )
            done["ok"] = r.json()["ok"]
            done["text"] = r.json()["text"]

        th = threading.Thread(target=attack)
        th.start()
        time.sleep(0.3)
        t = time.perf_counter()
        assert b.worker.http.get("/healthz").status_code == 200
        stalled = time.perf_counter() - t
        th.join()
    assert stalled < 1.0, f"/healthz waited {stalled:.2f}s behind one read"
    # 6.5 MB of raw data is over the 2 MiB cap: refused before any redaction.
    assert "result too large" in done["text"]


def test_inbound_args_digest_is_keyed(tmp_path, monkeypatch):
    orig = broker_fx.write_credentials

    def with_key(directory, keys):
        orig(directory, keys)
        p = directory / "audit-hmac.key"
        p.write_text(secrets.token_hex(32))
        os.chmod(p, 0o400)

    monkeypatch.setattr(broker_fx, "write_credentials", with_key)
    args = {
        "node": "pve1",
        "vmid": 100,
        "snapname": "preop",
        "description": "pre-op snapshot, patient SSN 123-45-6789",
    }
    with running_broker(tmp_path) as b:
        b.worker.execute(USERS["operator"].email, "create_vm_snapshot", args)
        lines = audit_lines()
    tool_lines = [x for x in lines if x.get("target") == "create_vm_snapshot"]
    assert tool_lines and all("mac" in x for x in tool_lines)
    plain = hashlib.sha256(
        json.dumps(args, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    plain_ascii = hashlib.sha256(
        json.dumps(
            args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
        ).encode()
    ).hexdigest()
    for line in lines:
        assert line.get("args_sha256") not in (plain, plain_ascii)


def test_abandoned_request_is_not_audited_as_ok(tmp_path):
    with running_broker(tmp_path) as b:
        http = b.worker.http
        body = b'{"tool":"list_nodes","arguments":{}}'
        hdrs = b.worker._headers(USERS["ro"].email, body, "POST", "/v1/execute")
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/execute",
            "raw_path": b"/v1/execute",
            "query_string": b"",
            "headers": [(k.encode(), v.encode()) for k, v in hdrs.items()]
            + [(b"content-type", b"application/json")],
            "http_version": "1.1",
            "scheme": "http",
            "client": ("127.0.0.1", 1),
            "server": (BROKER_HOST, 80),
        }

        async def receive():
            return {"type": "http.disconnect"}

        async def send(message):
            pass

        http.portal.call(http.app, scope, receive, send)
        line = [x for x in audit_lines() if x.get("event") in ("http", "catalog")][-1]
    assert line["status"] == "aborted" and line["http"] == 0
    assert line["deny"] == "client disconnected"
