"""H5: what a line may and must contain (no values, secrets or PHI; SOC 2 fields)."""

from __future__ import annotations

import datetime as dt
import json
import random
import re
import string

import pytest

from proxmox_mcp import audit
from proxmox_mcp.identity import Identity, current_identity


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "audit.jsonl"
    monkeypatch.setenv("MCP_AUDIT_LOG", str(path))
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    audit.reset_for_tests()
    yield path
    audit.reset_for_tests()


def recs(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


# Values that must never appear in a line, whatever field carries them.
SENSITIVE = [
    "PVEAPIToken=alice@pve!mcp=0b6c0b9e-5a8e-4c41-9d0e-7f1b2c3d4e5f",
    "0b6c0b9e-5a8e-4c41-9d0e-7f1b2c3d4e5f",
    "Bearer abcdefghijklmnopqrstuvwxyz0123456789",
    "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhQGV4YW1wbGUuY29tIn0.c2lnbmF0dXJlLXZhbHVl",
    "123-45-6789",
    "SSN 123456789",
    "1EG4-TE5-MK73",
    "MRN: 00123456",
    "DOB 03/14/1961",
    "4111 1111 1111 1111",
    "password=hunter2xyz",
    "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----",
    "PVEAuthCookie=PVE:root@pam:65F0A1B2::abcdefSIGNATURE",
]

NEEDLES = {
    SENSITIVE[0]: ["0b6c0b9e-5a8e-4c41-9d0e-7f1b2c3d4e5f"],
    SENSITIVE[1]: ["0b6c0b9e-5a8e-4c41-9d0e-7f1b2c3d4e5f"],
    SENSITIVE[2]: ["abcdefghijklmnopqrstuvwxyz0123456789"],
    SENSITIVE[3]: ["eyJzdWIiOiJhQGV4YW1wbGUuY29tIn0", "c2lnbmF0dXJlLXZhbHVl"],
    SENSITIVE[4]: ["123-45-6789"],
    SENSITIVE[5]: ["123456789"],
    SENSITIVE[6]: ["1EG4-TE5-MK73"],
    SENSITIVE[7]: ["00123456"],
    SENSITIVE[8]: ["03/14/1961"],
    SENSITIVE[9]: ["4111 1111 1111 1111"],
    SENSITIVE[10]: ["hunter2xyz"],
    SENSITIVE[11]: ["MIIEvQIBADANBg"],
    SENSITIVE[12]: ["abcdefSIGNATURE"],
}


def _rand_word(rng: random.Random, n: int = 8) -> str:
    return "".join(rng.choice(string.ascii_letters) for _ in range(n))


def _rand_value(rng: random.Random, depth: int = 0):
    roll = rng.random()
    if depth < 3 and roll < 0.2:
        return {_rand_word(rng): _rand_value(rng, depth + 1) for _ in range(rng.randint(1, 3))}
    if depth < 3 and roll < 0.35:
        return [_rand_value(rng, depth + 1) for _ in range(rng.randint(1, 3))]
    return f"{_rand_word(rng, 3)} {rng.choice(SENSITIVE)} {_rand_word(rng, 3)}"


@pytest.mark.parametrize("seed", range(25))
def test_property_no_values_secrets_or_phi(log_path, seed):
    rng = random.Random(seed)
    args = {_rand_word(rng): _rand_value(rng) for _ in range(rng.randint(1, 6))}
    # A PHI-bearing key name too: keys are recorded, so they are sanitized.
    args[rng.choice(SENSITIVE)] = 1
    free_text = rng.choice(SENSITIVE)
    audit.audit_event(
        side="in", user="a@example.com", kind="user", tool="execute_tool",
        target=rng.choice(["list_nodes", rng.choice(SENSITIVE)]),
        args=args,
        arg_keys=sorted(args),
        deny=f"refused: {free_text}",
        error=rng.choice(SENSITIVE),
        path=f"/nodes/pve/qemu/100/{rng.choice(SENSITIVE)}",
        data={"description": rng.choice(SENSITIVE)},
        notes=[rng.choice(SENSITIVE), {"x": rng.choice(SENSITIVE)}],
        **{rng.choice(["password", "api_key", "authorization", "cookie", "private_key"]):
           rng.choice(SENSITIVE)},
    )
    text = log_path.read_text()
    for value in SENSITIVE:
        for needle in NEEDLES[value]:
            assert needle not in text, (seed, needle)
    rec = recs(log_path)[-1]
    assert rec["user"] == "a@example.com"
    assert len(rec["args_sha256"]) == 64 and "args" not in rec
    assert audit.verify_chain(log_path) == 0


def test_required_soc2_fields(log_path):
    token = current_identity.set(Identity(subject="a@example.com", kind="user", ray_id="8a1b2c3d4e5f6a7b-IAD"))
    try:
        with audit.bind(jti="11111111-2222-3333-4444-555555555555", svc="0123.access"):
            audit.audit_event(side="in", tool="execute_tool", target="list_nodes",
                              rpc="execute", status="denied", deny="mode ro")
    finally:
        current_identity.reset(token)
    rec = recs(log_path)[-1]
    # who
    assert rec["user"] == "a@example.com" and rec["svc"] == "0123.access"
    # what / outcome
    assert rec["target"] == "list_nodes" and rec["status"] == "denied" and rec["deny"] == "mode ro"
    # when: UTC with milliseconds, plus a monotonic clock and the writer pid
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", rec["ts"])
    dt.datetime.fromisoformat(rec["ts"].replace("Z", "+00:00"))
    assert isinstance(rec["mono"], float) and rec["pid"] > 0
    # where / correlation
    assert rec["ray"] == "8a1b2c3d4e5f6a7b-IAD"
    assert rec["jti"] == "11111111-2222-3333-4444-555555555555"
    assert re.fullmatch(r"[0-9a-f]{32}", rec["eid"])


def test_mono_is_monotonic_within_a_process(log_path):
    for _ in range(5):
        audit.audit_event(kind="x")
    monos = [r["mono"] for r in recs(log_path)]
    assert monos == sorted(monos)


def test_explicit_fields_win_over_context(log_path):
    token = current_identity.set(Identity(subject="ctx@example.com", kind="user"))
    try:
        with audit.bind(jti="ctx"):
            audit.audit_event(user="explicit@example.com", jti="explicit")
    finally:
        current_identity.reset(token)
    rec = recs(log_path)[-1]
    assert rec["user"] == "explicit@example.com" and rec["jti"] == "explicit"


def test_bind_is_scoped(log_path):
    with audit.bind(jti="a"):
        pass
    audit.audit_event(kind="x")
    assert "jti" not in recs(log_path)[-1]


def test_reserved_fields_cannot_be_forged(log_path):
    audit.audit_event(kind="x", ts="1999", seq=-5, ph="genesis", mac="0" * 64, kid="evil",
                      mono=0.0, eid="e", pid=1)
    rec = recs(log_path)[-1]
    assert rec["seq"] == 1 and rec["ts"] != "1999" and rec["ph"] != "genesis"
    assert rec.get("kid") != "evil" and rec["eid"] != "e" and rec["pid"] != 1
    assert audit.verify_chain(log_path) == 0


def test_start_event_has_change_evidence(log_path):
    audit.start()
    rec = recs(log_path)[0]
    assert rec["kind"] == "start" and "version" in rec and "catalog_sha256" in rec
    assert rec["host"] and "hmac" in rec


def test_token_id_kept_but_secret_dropped(log_path):
    audit.audit_event(side="out", kind="proxmox", token_id="alice@pve!mcp",
                      method="GET", path="/nodes/pve/qemu/100/status/current", status=200)
    rec = recs(log_path)[-1]
    assert rec["token_id"] == "alice@pve!mcp"
    assert rec["path"] == "/nodes/pve/qemu/100/status/current"


def test_identifier_fields_sanitized(log_path):
    audit.audit_event(tool="list nodes; rm -rf /", target="x" * 500, method="GET\r\nX: y")
    rec = recs(log_path)[-1]
    for field in ("tool", "target", "method"):
        assert rec[field].startswith("sha256:"), field


def test_control_characters_cannot_split_lines(log_path):
    audit.audit_event(kind="x", deny="a\nb\r\n{\"seq\":0}")
    assert len(log_path.read_text().splitlines()) == 2
    assert audit.verify_chain(log_path) == 0
