"""H5: rotation continuity over audit-*.jsonl, gap detection, the auditor CLI."""

from __future__ import annotations

import json
import os

import pytest

from proxmox_mcp import audit


@pytest.fixture
def log_path(tmp_path, monkeypatch):
    path = tmp_path / "logs" / "audit.jsonl"
    monkeypatch.setenv("MCP_AUDIT_LOG", str(path))
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    audit.reset_for_tests()
    yield path
    audit.reset_for_tests()


def ship(log_path, name):
    shipped = log_path.parent / name
    os.rename(log_path, shipped)
    return shipped


def run_cli(capsys, argv):
    code = audit.main([str(a) for a in argv])
    out = capsys.readouterr().out
    return code, json.loads(out)


def make_rotated_set(log_path):
    """Three shipped months plus the live file, with restarts in between."""
    files = []
    for month in ("202607", "202608", "202609"):
        for i in range(3):
            audit.audit_event(kind="x", m=month, i=i)
        files.append(ship(log_path, f"audit-{month}.jsonl"))
        audit.reset_for_tests()  # service restart after each rotation
    audit.audit_event(kind="live")
    return files + [log_path]


def test_chain_spans_many_rotations(log_path):
    files = make_rotated_set(log_path)
    summary = audit.verify_files(files)
    assert summary["breaks"] == 0 and summary["gaps"] == []
    assert summary["first_seq"] == 0 and summary["last_seq"] == summary["lines"] - 1
    assert [f["path"] for f in summary["files"]] == [str(f) for f in files]


def test_rename_without_restart_spans_files(log_path):
    audit.audit_event(kind="a")
    first = ship(log_path, "audit-202609.jsonl")
    audit.audit_event(kind="b")
    second = ship(log_path, "audit-202610.jsonl")
    audit.audit_event(kind="c")
    assert audit.verify_files([first, second, log_path])["breaks"] == 0


def test_directory_mode_orders_by_seq(log_path, capsys):
    make_rotated_set(log_path)
    # Names that sort wrongly by name must still be ordered by their first seq.
    os.rename(log_path.parent / "audit-202607.jsonl", log_path.parent / "audit-z-oldest.jsonl")
    code, summary = run_cli(capsys, ["--dir", log_path.parent])
    assert code == 0 and summary["breaks"] == 0 and summary["ok"] is True
    assert summary["files"][0]["path"].endswith("audit-z-oldest.jsonl")
    assert summary["files"][-1]["path"].endswith("audit.jsonl")


def test_missing_middle_file_is_a_gap(log_path, capsys):
    files = make_rotated_set(log_path)
    files[1].unlink()
    code, summary = run_cli(capsys, ["--dir", log_path.parent])
    assert code == 1 and summary["ok"] is False
    gap = summary["gaps"][0]
    assert gap["expected"] < gap["got"]
    assert gap["path"].endswith("audit-202609.jsonl") and gap["line"] == 1


def test_wrong_order_breaks(log_path):
    files = make_rotated_set(log_path)
    assert audit.verify_files(list(reversed(files)))["breaks"] >= 1


def test_new_process_prefers_sibling_with_highest_seq(log_path):
    audit.audit_event(kind="x")
    newer = ship(log_path, "audit-202610.jsonl")
    older = log_path.parent / "audit-202609.jsonl"
    older.write_text(newer.read_text().splitlines()[0] + "\n")
    os.utime(older, (2_000_000_000, 2_000_000_000))  # newest mtime, lowest seq
    audit.reset_for_tests()
    audit.audit_event(kind="y")
    assert audit.verify_files([newer, log_path])["breaks"] == 0


def test_cli_summary_fields(log_path, capsys):
    audit.audit_event(kind="x")
    code, summary = run_cli(capsys, [log_path])
    assert code == 0
    for key in ("ok", "files", "lines", "breaks", "gaps", "problems", "first_ts", "last_ts",
                "first_seq", "last_seq", "last_hash", "mac", "anchor", "exit"):
        assert key in summary, key
    assert summary["lines"] == 2 and summary["mac"]["status"] == "absent"
    assert summary["first_ts"] <= summary["last_ts"]


def test_cli_exit_codes(log_path, tmp_path, capsys):
    audit.audit_event(kind="x")
    assert run_cli(capsys, [log_path])[0] == 0
    raw = log_path.read_text().splitlines()
    raw[0] = raw[0].replace('"kind":"start"', '"kind":"evil"')
    log_path.write_text("\n".join(raw) + "\n")
    assert run_cli(capsys, [log_path])[0] == 1
    code, summary = run_cli(capsys, [tmp_path / "missing.jsonl"])
    assert code == 2 and "error" in summary
    code, summary = run_cli(capsys, ["--bogus-flag"])
    assert code == 2 and "error" in summary
    code, summary = run_cli(capsys, [log_path, "--anchor", "not-an-anchor"])
    assert code == 2


def test_cli_require_mac_without_key_is_error(log_path, capsys):
    audit.audit_event(kind="x")
    code, summary = run_cli(capsys, [log_path, "--require-mac"])
    assert code == 1 and summary["mac"]["status"] == "absent"


def test_cli_key_file_and_anchor(log_path, tmp_path, monkeypatch, capsys):
    creds = tmp_path / "creds"
    creds.mkdir(mode=0o700)
    key = creds / audit.HMAC_CREDENTIAL
    key.write_text("ab" * 32)
    os.chmod(key, 0o400)
    monkeypatch.setenv("BROKER_CREDENTIALS_DIR", str(creds))
    audit.reset_for_tests()
    audit.audit_event(kind="x")
    monkeypatch.delenv("BROKER_CREDENTIALS_DIR")
    auditor_key = tmp_path / "copy.key"
    auditor_key.write_text("ab" * 32)
    code, summary = run_cli(capsys, [log_path, "--key-file", auditor_key, "--require-mac"])
    assert code == 0 and summary["mac"]["status"] == "verified"
    anchor = f"{summary['last_seq']}:{summary['last_hash']}"
    code, summary = run_cli(capsys, [log_path, "--key-file", auditor_key, "--anchor", anchor])
    assert code == 0 and summary["anchor"]["ok"] is True
    code, summary = run_cli(capsys, [log_path, "--anchor", f"99:{'0' * 64}"])
    assert code == 1 and summary["anchor"]["ok"] is False
    # Without a key the macs are unverified; --require-mac makes that a failure.
    assert run_cli(capsys, [log_path, "--require-mac"])[0] == 1


def test_cli_default_is_configured_directory(log_path, capsys):
    make_rotated_set(log_path)
    code, summary = run_cli(capsys, [])
    assert code == 0 and len(summary["files"]) == 4


def test_verify_never_writes(log_path, capsys):
    audit.audit_event(kind="x")
    before = {p.name: p.read_bytes() for p in log_path.parent.iterdir()}
    run_cli(capsys, ["--dir", log_path.parent])
    after = {p.name: p.read_bytes() for p in log_path.parent.iterdir() if not p.name.endswith(".lock")}
    assert {k: v for k, v in before.items() if not k.endswith(".lock")} == after
