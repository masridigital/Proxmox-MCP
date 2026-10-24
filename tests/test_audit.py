"""Hash-chained audit log."""

import json
import logging
import os
import sys

import pytest

from proxmox_mcp import audit


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "audit.jsonl"
    monkeypatch.setenv("MCP_AUDIT_LOG", str(path))
    audit.reset_for_tests()
    yield path
    audit.reset_for_tests()


def lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def test_start_event_chain_and_no_values(log_path):
    audit.audit_event(side="in", user="a@example.com", tool="get_vm_status",
                      args={"node": "pve", "vmid": 100, "description": "secret value"})
    audit.audit_event(side="out", user="a@example.com", method="GET", path="/nodes", status=200)
    recs = lines(log_path)
    assert recs[0]["kind"] == "start" and recs[0]["ph"] == "genesis" and "version" in recs[0]
    assert "catalog_sha256" in recs[0]
    assert [r["seq"] for r in recs] == [0, 1, 2]
    assert recs[1]["arg_keys"] == ["description", "node", "vmid"]
    assert len(recs[1]["args_sha256"]) == 64 and "args" not in recs[1]
    assert "secret value" not in log_path.read_text()
    assert recs[1]["ts"].endswith("Z")
    assert audit.verify_chain(log_path) == 0
    assert audit.main([str(log_path)]) == 0


def test_args_hash_is_canonical():
    assert audit.canonical_args_hash({"a": 1, "b": 2}) == audit.canonical_args_hash({"b": 2, "a": 1})


def test_secret_looking_fields_dropped(log_path):
    audit.audit_event(kind="x", password="hunter2", authorization="PVEAPIToken=x", ticket="t")
    text = log_path.read_text()
    assert "hunter2" not in text and "PVEAPIToken" not in text


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_file_and_dir_modes(log_path):
    audit.audit_event(kind="x")
    assert (os.stat(log_path).st_mode & 0o777) == 0o600
    assert (os.stat(log_path.parent).st_mode & 0o777) == 0o700


def test_tamper_detected(log_path):
    for i in range(5):
        audit.audit_event(kind="x", n=i)
    raw = log_path.read_text().splitlines()
    raw[3] = raw[3].replace('"n":2', '"n":9')
    log_path.write_text("\n".join(raw) + "\n")
    assert audit.verify_chain(log_path) >= 1
    assert audit.main([str(log_path)]) == 1


def test_deleted_line_detected(log_path):
    for i in range(4):
        audit.audit_event(kind="x", n=i)
    raw = log_path.read_text().splitlines()
    del raw[2]
    log_path.write_text("\n".join(raw) + "\n")
    assert audit.verify_chain(log_path) >= 1


def test_restart_continues_chain(log_path):
    audit.audit_event(kind="x")
    audit.reset_for_tests()  # new process
    audit.audit_event(kind="y")
    recs = lines(log_path)
    assert [r["seq"] for r in recs] == [0, 1, 2, 3]  # start, x, start, y
    assert audit.verify_chain(log_path) == 0


def test_rename_spans_files(log_path):
    audit.audit_event(kind="x")
    shipped = log_path.parent / "audit-202610.jsonl"
    os.rename(log_path, shipped)  # what the shipper does
    audit.audit_event(kind="y")
    assert lines(log_path)[0]["ph"] != "genesis"
    assert audit.verify_chain([shipped, log_path]) == 0
    assert audit.main([str(shipped), str(log_path)]) == 0
    assert audit.verify_chain([log_path, shipped]) >= 1  # wrong order breaks


def test_new_process_chains_to_newest_sibling(log_path):
    audit.audit_event(kind="x")
    shipped = log_path.parent / "audit-202610.jsonl"
    os.rename(log_path, shipped)
    audit.reset_for_tests()  # restart with an empty live file and no memory
    audit.audit_event(kind="y")
    assert audit.verify_chain([shipped, log_path]) == 0
    assert lines(log_path)[0]["seq"] == lines(shipped)[-1]["seq"] + 1


def test_torn_line_counts_as_one_break(log_path):
    audit.audit_event(kind="x")
    with open(log_path, "ab") as fh:
        fh.write(b'{"ts":"2026')  # crash mid-write
    audit.reset_for_tests()
    audit.audit_event(kind="y")
    assert all(line for line in log_path.read_text().split("\n")[:-1])
    assert audit.verify_chain(log_path) == 1


def test_write_failure_raises(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("MCP_AUDIT_LOG", str(blocker / "audit.jsonl"))
    audit.reset_for_tests()
    with pytest.raises(audit.AuditError):
        audit.audit_event(kind="x")
    audit.reset_for_tests()


def test_logging_mirror(log_path, caplog):
    with caplog.at_level(logging.INFO, logger="proxmox_mcp.audit"):
        audit.audit_event(kind="mirror")
    assert any('"kind":"mirror"' in r.getMessage() for r in caplog.records)


def test_verify_missing_file_exit_2(tmp_path):
    assert audit.main([str(tmp_path / "nope.jsonl")]) == 2


def test_default_path_per_os(monkeypatch):
    monkeypatch.setattr(audit, "IS_WINDOWS", True)
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    assert audit.default_path().endswith(os.path.join("ProxmoxMCP", "logs", "audit.jsonl"))
    monkeypatch.setattr(audit, "IS_WINDOWS", False)
    assert audit.default_path() == "/var/log/proxmox-mcp/audit.jsonl"
