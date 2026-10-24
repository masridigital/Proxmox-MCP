"""H5: concurrency, crash safety, ENOSPC fail-closed, single-write lines, line cap."""

from __future__ import annotations

import asyncio
import errno
import json
import multiprocessing
import os
import sys
import threading

import pytest

from proxmox_mcp import audit, server
from proxmox_mcp.identity import Identity


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


def test_threads_and_tasks_keep_one_chain(log_path):
    def worker(n):
        for i in range(40):
            audit.audit_event(kind="thread", t=n, i=i)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]

    async def tasks():
        async def one(i):
            await asyncio.sleep(0)
            audit.audit_event(kind="task", i=i)

        await asyncio.gather(
            *(one(i) for i in range(40)),
            *(asyncio.to_thread(audit.audit_event, kind="to_thread", i=i) for i in range(40)),
        )

    for t in threads:
        t.start()
    asyncio.run(tasks())
    for t in threads:
        t.join()
    lines = recs(log_path)
    assert len(lines) == 1 + 6 * 40 + 80
    assert [r["seq"] for r in lines] == list(range(len(lines)))
    assert audit.verify_chain(log_path) == 0


def _child(path: str, n: int) -> None:
    os.environ["MCP_AUDIT_LOG"] = path
    audit.reset_for_tests()
    for i in range(25):
        audit.audit_event(kind="proc", p=n, i=i)


@pytest.mark.skipif(sys.platform == "win32", reason="fork start method")
def test_processes_share_one_chain(log_path):
    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=_child, args=(str(log_path), n)) for n in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    lines = recs(log_path)
    assert len(lines) == 4 * 26
    assert [r["seq"] for r in lines] == list(range(len(lines)))
    assert audit.verify_files([log_path])["breaks"] == 0


def test_each_line_is_one_write(log_path, monkeypatch):
    calls = []
    real = audit._write_fd

    def spy(fd, data):
        calls.append(bytes(data))
        return real(fd, data)

    monkeypatch.setattr(audit, "_write_fd", spy)
    audit.audit_event(kind="x")
    audit.audit_event(kind="y")
    assert len(calls) == 3  # start, x, y
    assert all(c.endswith(b"\n") and c.count(b"\n") == 1 for c in calls)


def test_torn_tail_terminated_in_same_write(log_path, monkeypatch):
    audit.audit_event(kind="x")
    with open(log_path, "ab") as fh:
        fh.write(b'{"ts":"2026')
    calls = []
    real = audit._write_fd
    monkeypatch.setattr(audit, "_write_fd", lambda fd, d: (calls.append(bytes(d)), real(fd, d))[1])
    audit.reset_for_tests()
    audit.audit_event(kind="y")
    assert len(calls) == 2 and calls[0].startswith(b"\n{")
    summary = audit.verify_files([log_path])
    assert summary["breaks"] == 1
    # seq does not restart at 0 after a torn line; the torn line consumed one seq.
    seqs = [json.loads(x)["seq"] for x in log_path.read_text().splitlines() if x.endswith("}")]
    assert seqs == [0, 1, 3, 4]


def test_enospc_fails_closed_and_is_visible(log_path, monkeypatch, caplog):
    audit.audit_event(kind="x")

    def full(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(audit, "_write_fd", full)
    with pytest.raises(audit.AuditError):
        audit.audit_event(kind="y")
    h = audit.health()
    assert h["ok"] is False and h["last_error"] == "ENOSPC" and h["failures"] == 1
    assert any("ENOSPC" in r.getMessage() for r in caplog.records if r.levelname == "CRITICAL")
    monkeypatch.setattr(audit, "_write_fd", os.write)
    audit.audit_event(kind="z")
    assert audit.health()["ok"] is True and audit.health()["failures"] == 1
    assert audit.verify_chain(log_path) == 0


def test_short_write_is_completed(log_path, monkeypatch):
    real = audit._write_fd
    state = {"first": True}

    def short(fd, data):
        if state["first"] and len(data) > 10:
            state["first"] = False
            return real(fd, data[:10])
        return real(fd, data)

    monkeypatch.setattr(audit, "_write_fd", short)
    audit.audit_event(kind="x")
    assert audit.verify_chain(log_path) == 0


def test_fsync_per_line(log_path, monkeypatch):
    calls = []
    monkeypatch.setattr(audit, "_fsync", lambda fd: calls.append(fd))
    audit.audit_event(kind="x")
    audit.audit_event(kind="y")
    assert len(calls) >= 3


def test_fsync_failure_fails_closed(log_path, monkeypatch):
    audit.audit_event(kind="x")

    def bad(fd):
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(audit, "_fsync", bad)
    with pytest.raises(audit.AuditError):
        audit.audit_event(kind="y")
    assert audit.health()["last_error"] == "EIO"


def test_windows_code_path(log_path, monkeypatch):
    # No fchmod, no directory fsync on Windows; os.fsync on the file descriptor only.
    monkeypatch.setattr(audit, "IS_WINDOWS", True)
    monkeypatch.setattr(audit.os, "fchmod", None, raising=False)
    fsyncs = []
    monkeypatch.setattr(audit, "_fsync", lambda fd: fsyncs.append(fd))
    audit.audit_event(kind="x")
    assert len(fsyncs) == 2 and audit.verify_chain(log_path) == 0


def test_line_cap(log_path):
    huge = {f"k{i}": "v" * 1000 for i in range(40)}
    audit.audit_event(
        kind="x",
        user="a@example.com",
        status="ok",
        notes=["n" * 1000] * 50,
        extra="e" * 5000,
        more=huge,
    )
    line = log_path.read_text().splitlines()[-1]
    assert len(line.encode()) <= audit.MAX_LINE_BYTES
    rec = json.loads(line)
    assert rec["user"] == "a@example.com" and rec["status"] == "ok" and rec["kind"] == "x"
    assert audit.verify_chain(log_path) == 0


def test_symlinked_log_refused(tmp_path, monkeypatch):
    if sys.platform == "win32":
        pytest.skip("symlinks need privilege on Windows")
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("")
    link = tmp_path / "logs" / "audit.jsonl"
    link.parent.mkdir()
    link.symlink_to(target)
    monkeypatch.setenv("MCP_AUDIT_LOG", str(link))
    audit.reset_for_tests()
    with pytest.raises(audit.AuditError):
        audit.audit_event(kind="x")
    audit.reset_for_tests()


# ---- the server pipeline fails closed when the audit write fails ----------------


class FakeProxmox:
    async def get(self, path, params=None):
        return {"data": []}

    async def close(self):
        pass


async def test_tool_call_denied_when_audit_cannot_be_written(log_path, tmp_path, monkeypatch):
    enrollment = tmp_path / "enrollment.json"
    enrollment.write_text(
        json.dumps(
            {
                "users": {
                    "alice@example.com": {
                        "mode": "ro",
                        "proxmox_userid": "alice@pve",
                        "token_credential": "pve-token-alice",
                    }
                }
            }
        )
    )
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", str(enrollment))
    monkeypatch.setattr(server, "proxmox", FakeProxmox())
    called = []
    module = server.router.REGISTRY["list_nodes"][1]

    async def handle(*a, **k):
        called.append(1)
        return {"data": []}

    monkeypatch.setattr(module, "handle", handle)

    def full(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(audit, "_write_fd", full)
    ok, text = await server.run_tool(
        Identity(subject="alice@example.com", kind="user", email="alice@example.com"),
        "list_nodes",
        {},
    )
    assert ok is False and called == []
    assert audit.health()["ok"] is False
