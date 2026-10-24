"""Hash-chained JSONL audit log (MCP-STD-01 5.9; HIPAA 164.312(b) and (c)(1); SOC 2 CC7.2).

One JSON object per line, keys in this order: ``ts`` (UTC ISO 8601, ms), ``seq``
(monotonic per file chain), ``ph`` (sha256 hex of the previous line's bytes, without
its newline), then the event fields. The same line is emitted on the logging
logger ``proxmox_mcp.audit`` (journald / Windows Event Log via the service host).

No values: an ``args`` field is replaced by ``arg_keys`` (sorted) and
``args_sha256`` (sha256 of canonical JSON). Long strings are capped. Callers must
not pass secrets; keys that look secret are dropped defensively.

Chain anchors and rotation (decided with DEPLOY):
- the broker never rotates. Each event opens the file (O_APPEND|O_CREAT|O_WRONLY,
  plus O_BINARY on Windows), writes the line with a single write, fsyncs and
  closes, so the Windows shipper can read and rename audit.jsonl to
  audit-YYYYMM.jsonl between writes;
- ``ph`` is the hash of the live file's last line; when the file is missing or
  empty it is the hash of the last line this process wrote (the chain spans the
  rename), else the last line of the newest audit-*.jsonl sibling, else
  ``"genesis"``; ``seq`` continues the same way;
- a torn last line (crash mid-write) is newline-terminated and chained to as-is;
  the verifier reports it as one break, which is the truth;
- ``proxmox-mcp-audit-verify audit-202609.jsonl audit-202610.jsonl audit.jsonl``
  checks continuity across files in the order given (first line of the first
  file is the anchor).

Integrity against an administrator who can rewrite the whole set comes from
shipping: the Windows scheduled task (DEPLOY) ships the log every 5 minutes to
WORM storage (immutable blob container / R2 bucket lock) and runs the verifier.
The first event of each process is a "start" event with the package version and
the sha256 of the tool catalog (SOC 2 CC8.1 change evidence).

Durability: fsync per line (audit volume is small). A write failure raises
AuditError: callers fail closed.

Path: MCP_AUDIT_LOG, default %ProgramData%\\ProxmoxMCP\\logs\\audit.jsonl on
Windows and /var/log/proxmox-mcp/audit.jsonl elsewhere. On POSIX the directory is
created 0700 and the file 0600; on Windows the installer ACLs the directory
(service SID write, Administrators read).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import logging
import os
import re
import sys
import threading
from collections.abc import Iterable
from typing import Any

logger = logging.getLogger("proxmox_mcp.audit")

GENESIS = "genesis"
MAX_FIELD_CHARS = 1024
_RESERVED = ("ts", "seq", "ph")
_SECRET_FIELD_RE = re.compile(r"(?i)(password|secret|token_value|authorization|cookie|ticket)")
IS_WINDOWS = sys.platform == "win32"


class AuditError(RuntimeError):
    """The audit line could not be written; the caller must not proceed."""


def default_path() -> str:
    if IS_WINDOWS:
        base = os.environ.get("ProgramData") or r"C:\ProgramData"
        return os.path.join(base, "ProxmoxMCP", "logs", "audit.jsonl")
    return "/var/log/proxmox-mcp/audit.jsonl"


def configured_path() -> str:
    return os.environ.get("MCP_AUDIT_LOG") or default_path()


def line_hash(line: bytes) -> str:
    return hashlib.sha256(line.rstrip(b"\r\n")).hexdigest()


def canonical_args_hash(args: Any) -> str:
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _clean(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[nested]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= MAX_FIELD_CHARS else value[:MAX_FIELD_CHARS] + "..."
    if isinstance(value, dict):
        return {str(k): _clean(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_clean(v, depth + 1) for v in list(value)[:50]]
    return _clean(str(value), depth)


def build_fields(fields: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in fields.items():
        if key in _RESERVED or _SECRET_FIELD_RE.search(key):
            continue
        if key == "args":
            args = value if isinstance(value, dict) else {}
            out["arg_keys"] = sorted(str(k) for k in args)
            out["args_sha256"] = canonical_args_hash(args)
            continue
        out[key] = _clean(value)
    return out


def _read_last_line(path: str) -> bytes | None:
    """The last non-empty line of a file (without newline), or None if missing/empty."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            data = b""
            while pos > 0:
                step = min(4096, pos)
                pos -= step
                fh.seek(pos)
                data = fh.read(step) + data
                if data.rstrip(b"\r\n").count(b"\n") >= 1:
                    break
    except (FileNotFoundError, NotADirectoryError):
        return None
    data = data.rstrip(b"\r\n")
    return data.rsplit(b"\n", 1)[-1] if data else None


def _newest_sibling(path: str) -> str | None:
    """The newest shipped file (audit-*.jsonl next to the live log), by mtime then name."""
    directory = os.path.dirname(path) or "."
    stem = os.path.splitext(os.path.basename(path))[0]
    try:
        names = [
            n for n in os.listdir(directory)
            if n.startswith(stem + "-") and n.endswith(".jsonl")
        ]
    except OSError:
        return None
    if not names:
        return None
    full = [os.path.join(directory, n) for n in names]
    return max(full, key=lambda f: (os.path.getmtime(f), f))


def _seq_of(line: bytes) -> int | None:
    try:
        seq = json.loads(line).get("seq")
    except (ValueError, AttributeError):
        return None
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else None


class AuditLog:
    """Open, append, fsync and close per event.

    The broker never rotates. Closing after every line lets the Windows shipper read
    and rename audit.jsonl to audit-YYYYMM.jsonl between writes. The chain head is
    taken from the live file's last line when it has one; when the file is missing
    or empty it comes from memory (the hash of the last line this process wrote, so
    the chain spans the rename), else from the newest audit-*.jsonl sibling, else
    "genesis".
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._prev_hash: str | None = None
        self._seq: int | None = None
        self._started = False

    def _head(self) -> tuple[str, int]:
        last = _read_last_line(self.path)
        if last is None and self._prev_hash is not None:
            return self._prev_hash, self._seq or 0
        if last is None:
            sibling = _newest_sibling(self.path)
            last = _read_last_line(sibling) if sibling else None
        if last is None:
            return GENESIS, 0
        seq = _seq_of(last)
        return line_hash(last), (seq + 1 if seq is not None else (self._seq or 0))

    def _append(self, data: bytes) -> None:
        directory = os.path.dirname(self.path) or "."
        if not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            if not IS_WINDOWS and os.fstat(fd).st_mode & 0o077:
                os.fchmod(fd, 0o600)
            # A torn last line (crash mid-write) is terminated so ours starts clean.
            if os.fstat(fd).st_size and not self._ends_with_newline():
                os.write(fd, b"\n")
            if os.write(fd, data) != len(data):
                raise OSError("short write")
            os.fsync(fd)
        finally:
            os.close(fd)

    def _ends_with_newline(self) -> bool:
        with open(self.path, "rb") as fh:
            fh.seek(-1, os.SEEK_END)
            return fh.read(1) == b"\n"

    def write(self, fields: dict[str, Any]) -> str:
        record_fields = build_fields(fields)
        with self._lock:
            try:
                prev_hash, seq = self._head()
                now = _dt.datetime.now(_dt.timezone.utc)
                record = {
                    "ts": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                    "seq": seq,
                    "ph": prev_hash,
                    **record_fields,
                }
                line = json.dumps(record, separators=(",", ":"), ensure_ascii=True, default=str)
                data = line.encode("ascii") + b"\n"
                self._append(data)
                self._prev_hash = line_hash(data)
                self._seq = seq + 1
            except Exception as exc:
                logger.critical("audit write failed: %s", type(exc).__name__)
                raise AuditError("audit log unavailable") from None
        logger.info(line)
        return line

    def close(self) -> None:
        """Nothing is held open between events."""


_lock = threading.Lock()
_log: AuditLog | None = None


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("proxmox-mcp-server")
    except Exception:
        return "unknown"


def _catalog_hash() -> str | None:
    """sha256 of the canonical tool catalog (names, schemas) if the router is importable."""
    try:
        from . import router  # lazy: owned by another module, may import tools

        registry = getattr(router, "REGISTRY", None)
        if not registry:
            return None
        catalog = [registry[name][0] for name in sorted(registry)]
        return canonical_args_hash(catalog)
    except Exception:
        return None


def _get_log() -> AuditLog:
    global _log
    with _lock:
        path = configured_path()
        if _log is None or _log.path != path:
            if _log is not None:
                _log.close()
            _log = AuditLog(path)
        log = _log
    if not log._started:
        log._started = True
        log.write(
            {
                "side": "broker",
                "kind": "start",
                "version": _version(),
                "catalog_sha256": _catalog_hash(),
                "pid": os.getpid(),
            }
        )
    return log


def start() -> None:
    """Open the log and write the start event (version + catalog hash). Idempotent."""
    _get_log()


def audit_event(**fields: Any) -> None:
    """Append one hash-chained line. Raises AuditError if it cannot be written."""
    _get_log().write(fields)


def reset_for_tests() -> None:
    global _log
    with _lock:
        if _log is not None:
            _log.close()
        _log = None


# --- verification ------------------------------------------------------------------


def verify_lines(lines: Iterable[bytes], prev_hash: str | None = None) -> tuple[int, int, str | None]:
    """(lines, breaks, last_hash). The first line is the anchor when prev_hash is None."""
    count = breaks = 0
    prev_seq: int | None = None
    for raw in lines:
        raw = raw.rstrip(b"\r\n")
        if not raw:
            continue
        count += 1
        try:
            record = json.loads(raw)
            ph, seq = record["ph"], record["seq"]
            # First line of a lone file: its ph is the anchor ("genesis" or a rotated-from hash).
            ok = isinstance(ph, str) if prev_hash is None else ph == prev_hash
            if prev_seq is not None and seq != prev_seq + 1:
                ok = False
            prev_seq = seq if isinstance(seq, int) else None
        except (ValueError, KeyError, TypeError):
            ok = False
            prev_seq = None
        if not ok:
            breaks += 1
        prev_hash = line_hash(raw)
    return count, breaks, prev_hash


def verify_chain(paths: str | os.PathLike | Iterable[str | os.PathLike], prev_hash: str | None = None) -> int:
    """Number of chain breaks across one file or several files in order (0 = intact).

    The first line of the first file is the anchor unless prev_hash is given;
    every later line, including the first line of each following file, must
    carry the hash of the line before it.
    """
    if isinstance(paths, (str, os.PathLike)):
        paths = [paths]
    breaks = 0
    for path in paths:
        with open(path, "rb") as fh:
            _, file_breaks, prev_hash = verify_lines(fh, prev_hash)
        breaks += file_breaks
    return breaks


def main(argv: list[str] | None = None) -> int:
    """``proxmox-mcp-audit-verify FILE [FILE...]`` (oldest first). Exit 0 intact, 1 breaks, 2 error."""
    files = list(sys.argv[1:] if argv is None else argv)
    if not files:
        files = [configured_path()]
    prev: str | None = None
    total_lines = total_breaks = 0
    for path in files:
        try:
            with open(path, "rb") as fh:
                lines, breaks, prev = verify_lines(fh, prev)
        except OSError as exc:
            print(f"{path}: cannot read ({type(exc).__name__})", file=sys.stderr)
            return 2
        print(f"{path}: {lines} lines, {breaks} breaks")
        total_lines += lines
        total_breaks += breaks
    print(f"total: {total_lines} lines, {total_breaks} breaks")
    return 1 if total_breaks else 0


if __name__ == "__main__":
    sys.exit(main())
