"""H5: keyed integrity (HMAC chain), downgrade and truncation detection."""

from __future__ import annotations

import hashlib
import json
import os
import re

import pytest

from proxmox_mcp import audit

KEY_HEX = "11" * 32
KEY2_HEX = "22" * 32


@pytest.fixture
def creds(tmp_path, monkeypatch):
    directory = tmp_path / "creds"
    directory.mkdir(mode=0o700)
    monkeypatch.setenv("BROKER_CREDENTIALS_DIR", str(directory))
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.delenv("MCP_AUDIT_HMAC", raising=False)
    return directory


def put_key(directory, text=KEY_HEX):
    path = directory / audit.HMAC_CREDENTIAL
    path.write_text(text + "\n")
    os.chmod(path, 0o400)
    return path


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "audit.jsonl"
    monkeypatch.setenv("MCP_AUDIT_LOG", str(path))
    audit.reset_for_tests()
    yield path
    audit.reset_for_tests()


def recs(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def keyfile(tmp_path, hexkey=KEY_HEX):
    path = tmp_path / f"auditor-{hexkey[:4]}.key"
    path.write_text(hexkey)
    return path


def test_every_line_carries_mac_when_key_present(creds, log_path):
    put_key(creds)
    audit.audit_event(side="in", user="a@example.com", tool="list_nodes")
    lines = recs(log_path)
    assert all(re.fullmatch(r"[0-9a-f]{64}", r["mac"]) for r in lines)
    assert len({r["kid"] for r in lines}) == 1
    # mac is the last key, so the verifier can recover the signed bytes exactly.
    assert all(
        line.endswith('"}') and '"mac":"' in line.rsplit(",", 1)[-1]
        for line in log_path.read_text().splitlines()
    )
    summary = audit.verify_files([log_path], keys=audit.load_key_files([keyfile(log_path.parent)]))
    assert summary["breaks"] == 0 and summary["mac"]["status"] == "verified"


def test_no_key_no_mac(creds, log_path):
    audit.audit_event(kind="x")
    assert all("mac" not in r for r in recs(log_path))
    assert audit.verify_files([log_path])["mac"]["status"] == "absent"


def test_tail_rewrite_with_recomputed_sha256_is_detected(creds, log_path, tmp_path):
    """The attack a plain hash chain cannot see: edit a line and re-hash everything after it."""
    put_key(creds)
    for i in range(5):
        audit.audit_event(kind="x", n=i)
    raw = log_path.read_text().splitlines()
    forged = [raw[0], raw[1]]
    for line in raw[2:]:
        rec = json.loads(line)
        rec["ph"] = hashlib.sha256(forged[-1].encode()).hexdigest()
        if rec.get("n") == 2:
            rec["n"] = 99
        forged.append(json.dumps(rec, separators=(",", ":")))
    log_path.write_text("\n".join(forged) + "\n")
    # The unkeyed chain is consistent again: exactly what an attacker wants.
    assert audit.verify_chain(log_path) == 0
    summary = audit.verify_files([log_path], keys=audit.load_key_files([keyfile(tmp_path)]))
    assert summary["breaks"] >= 1 and summary["mac"]["status"] == "invalid"
    assert summary["mac"]["invalid"] >= 1


def test_wrong_key_is_invalid(creds, log_path, tmp_path):
    put_key(creds)
    audit.audit_event(kind="x")
    summary = audit.verify_files([log_path], keys={})
    assert summary["mac"]["status"] == "unverified" and summary["breaks"] == 0
    other = audit.load_key_files([keyfile(tmp_path, KEY2_HEX)])
    summary = audit.verify_files([log_path], keys=other)
    # Unknown key id: cannot verify, never silently "verified".
    assert summary["mac"]["status"] == "unverified"
    summary = audit.verify_files([log_path], keys=other, require_mac=True)
    assert summary["breaks"] >= 1


def test_downgrade_detected_by_verifier(creds, log_path, tmp_path):
    put_key(creds)
    for i in range(3):
        audit.audit_event(kind="x", n=i)
    raw = log_path.read_text().splitlines()
    # Attacker strips the mac from the tail and re-chains it as a plain line.
    rec = json.loads(raw[-1])
    rec.pop("mac")
    rec.pop("kid")
    rec["ph"] = hashlib.sha256(raw[-2].encode()).hexdigest()
    raw[-1] = json.dumps(rec, separators=(",", ":"))
    log_path.write_text("\n".join(raw) + "\n")
    summary = audit.verify_files([log_path])
    assert summary["breaks"] == 1
    assert "mac_missing" in summary["problems"][0]["reasons"]


def test_writer_refuses_downgrade_when_key_disappears(creds, log_path):
    key = put_key(creds)
    audit.audit_event(kind="x")
    os.chmod(key, 0o600)
    key.unlink()
    audit.reset_for_tests()  # restart without the key
    with pytest.raises(audit.AuditError):
        audit.audit_event(kind="y")
    assert audit.health()["ok"] is False


def test_key_rotation_two_kids(creds, log_path, tmp_path):
    key = put_key(creds)
    audit.audit_event(kind="x")
    os.chmod(key, 0o600)
    key.unlink()
    put_key(creds, KEY2_HEX)
    audit.reset_for_tests()
    audit.audit_event(kind="y")
    assert len({r["kid"] for r in recs(log_path)}) == 2
    keys = audit.load_key_files([keyfile(tmp_path), keyfile(tmp_path, KEY2_HEX)])
    summary = audit.verify_files([log_path], keys=keys)
    assert summary["breaks"] == 0 and summary["mac"]["status"] == "verified"
    assert len(summary["mac"]["kids"]) == 2


def test_required_mode_without_key_fails_closed(creds, log_path, monkeypatch):
    monkeypatch.setenv("MCP_AUDIT_HMAC", "required")
    with pytest.raises(audit.AuditError):
        audit.audit_event(kind="x")
    assert not log_path.exists() or log_path.read_text() == ""


def test_present_but_weak_key_fails_closed(creds, log_path):
    put_key(creds, "short")
    with pytest.raises(audit.AuditError):
        audit.audit_event(kind="x")


def test_bad_mode_value_fails_closed(creds, log_path, monkeypatch):
    monkeypatch.setenv("MCP_AUDIT_HMAC", "maybe")
    with pytest.raises(audit.AuditError):
        audit.audit_event(kind="x")


def test_off_mode_writes_no_mac(creds, log_path, monkeypatch):
    put_key(creds)
    monkeypatch.setenv("MCP_AUDIT_HMAC", "off")
    audit.audit_event(kind="x")
    assert all("mac" not in r for r in recs(log_path))


def test_key_never_in_log(creds, log_path):
    put_key(creds)
    audit.audit_event(kind="x")
    assert KEY_HEX not in log_path.read_text()
    assert bytes.fromhex(KEY_HEX).hex() not in log_path.read_text()


def test_truncation_detected_with_anchor(log_path):
    for i in range(6):
        audit.audit_event(kind="x", n=i)
    full = audit.verify_files([log_path])
    anchor = (full["last_seq"], full["last_hash"])
    raw = log_path.read_text().splitlines()
    log_path.write_text("\n".join(raw[:-2]) + "\n")  # drop the tail
    assert audit.verify_chain(log_path) == 0  # invisible without an anchor
    summary = audit.verify_files([log_path], anchor=anchor)
    assert summary["breaks"] >= 1 and summary["anchor"]["ok"] is False
    assert audit.verify_files([log_path], anchor=(2, "0" * 64))["anchor"]["ok"] is False
    good = audit.verify_files([log_path], anchor=(2, audit.line_hash(raw[2].encode())))
    assert good["anchor"]["ok"] is True and good["breaks"] == 0


def test_mac_covers_previous_line(creds, log_path, tmp_path):
    """Swapping two keyed lines breaks the chain even though each mac is valid."""
    put_key(creds)
    for i in range(4):
        audit.audit_event(kind="x", n=i)
    raw = log_path.read_text().splitlines()
    raw[2], raw[3] = raw[3], raw[2]
    log_path.write_text("\n".join(raw) + "\n")
    summary = audit.verify_files([log_path], keys=audit.load_key_files([keyfile(tmp_path)]))
    assert summary["breaks"] >= 1
