"""Keyed, hash-chained JSONL audit log (MCP-STD-01 5.9; HIPAA 164.312(b), 164.312(c)(1),
164.316(b)(2); SOC 2 CC4.1, CC7.2, CC7.3).

Line format
-----------
One JSON object per line, ASCII only (control characters escaped, so a value can
never split or forge a line), at most ``MAX_LINE_BYTES`` bytes. Keys in order:

  ts    UTC wall clock, ISO 8601 with milliseconds and ``Z``      (when)
  mono  this process's monotonic clock, seconds with ms precision (when; immune to
        wall-clock steps: within one ``pid`` the ts/mono deltas must agree)
  seq   chain sequence number, +1 per line across files and restarts
  ph    sha256 hex of the previous line's bytes (without newline), or "genesis"
  pid   writer process id
  eid   random event id (request correlation inside the broker)
  ...   the event fields: who (user, kind, svc), what (rpc, tool, target, method,
        path, arg_keys, args_sha256), where (ray, client), outcome (status, deny,
        error, bytes, ms), correlation (jti, request id)
  kid   HMAC key id                                   (only when a key is loaded)
  mac   HMAC-SHA256 of the line up to and excluding ``,"mac":...`` (always last)

Integrity scheme
----------------
* Hash chain: ``ph`` binds every line to its predecessor; ``seq`` makes deletions,
  insertions and reordering visible even when an attacker repairs ``ph``.
* Keyed chain: when the credential ``audit-hmac.key`` (credentials.read_credential:
  systemd credential on Linux, DPAPI/ACL'd file on Windows) is present, every line
  carries ``kid`` and ``mac = HMAC-SHA256(key, "proxmox-mcp-audit-v1\\0" || body)``
  where body is the exact line bytes before the mac. The mac covers ``ph``, which
  covers the previous line including its mac, so the chain is keyed end to end. An
  attacker who can write the log but cannot read the key (another local account, an
  administrator without the DPAPI entropy file, a backup operator, the shipper's
  storage) can no longer rewrite the tail and recompute the hashes, which a plain
  sha256 chain allows. ``kid`` = first 16 hex of sha256("proxmox-mcp-audit-kid\\0" ||
  key) lets the verifier hold several keys across rotation.
  MCP_AUDIT_HMAC: ``auto`` (default: use the key when the credential exists; a
  present but unreadable or weak key fails closed), ``required`` (no key = no
  audit = every call denied), ``off``.
* Downgrade: once the chain is keyed, the writer refuses to append unkeyed lines
  (auto/required) and the verifier reports any later unkeyed line as a break.
* Residual: the broker service identity holds the key, so an attacker running as
  that identity can forge lines from the moment of compromise; shipping bounds the
  exposure to the last unshipped interval (5 minutes).

Completeness (how an auditor proves nothing is missing)
-------------------------------------------------------
1. The shipper (DEPLOY) copies every rotated ``audit-*.jsonl`` and the live tail to a
   WORM container (time-based immutability >= 2190 days, 164.316(b)(2)); its
   delete/overwrite test proves the copies cannot change after upload.
2. After each upload it runs ``proxmox-mcp-audit-verify`` and stores the JSON
   summary (last_seq, last_hash) in the same WORM container: that is the anchor.
3. The auditor downloads the WORM set and runs
   ``proxmox-mcp-audit-verify --dir <set> --key-file <escrowed key> --require-mac
   --anchor <last_seq>:<last_hash>``. Exit 0 proves: every line is authentic
   (mac), no line was altered, inserted, reordered or removed inside the chain
   (ph + seq), no file is missing between the first and last (seq gaps are
   reported with file and line), and the tail was not truncated below the anchor.
4. The first line of the set is ``seq 0 / ph "genesis"`` (or the auditor holds the
   anchor of the previous retention window). Each process start writes a "start"
   event (version, catalog hash, host, pid, hmac kid): cross-check them against
   the service start events in the Windows System log.
A local administrator can still delete the whole local set; only the WORM copy and
its anchors make that detectable, which is why the shipper is part of the control.

Writing
-------
The broker never rotates. Each event, under a thread lock and an inter-process lock
(``<log>.lock``: flock on POSIX, msvcrt.locking on Windows), opens the log
(O_RDWR|O_APPEND|O_CREAT|O_NOFOLLOW, plus O_BINARY on Windows), reads the chain head
from the same descriptor, writes the line with ONE os.write (a torn predecessor's
missing newline is prepended to the same buffer), fsyncs (os.fsync works on file
descriptors on Windows too; the directory is fsynced on POSIX after creating the
file) and closes, so the shipper can rename audit.jsonl between writes.
Head: the live file's last line; if it is missing/empty, whichever of this
process's last line and the newest ``audit-*.jsonl`` sibling has the higher seq;
else "genesis". A torn line (crash mid-write) is newline-terminated, consumes one
seq, and is reported by the verifier as one break, which is the truth.
Any failure (ENOSPC, EIO, short write that cannot complete, lock timeout, key
problem) raises AuditError, logs CRITICAL with the errno name, and marks
``health()`` not ok: callers fail closed (the tool call is denied).

Content
-------
No values: ``args`` (and any dict) is reduced to sanitized keys + sha256 of the
canonical JSON. Secret-named fields are dropped; identifier fields must match a
strict pattern or are replaced by ``sha256:<16 hex>`` (or ``[REDACTED <phi type>]``);
paths are sanitized per segment; free text is scrubbed of tokens, JWTs, key
blocks and PHI patterns (phi.redact_phi). ``user``, ``ray`` come from the current
Identity and ``bind()`` adds request correlation (jti, svc) when the caller does
not pass them.

Path: MCP_AUDIT_LOG, default %ProgramData%\\ProxmoxMCP\\logs\\audit.jsonl on Windows
and /var/log/proxmox-mcp/audit.jsonl elsewhere (directory 0700, file 0600 on POSIX;
on Windows the installer ACLs the directory).
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import errno as _errno
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import sys
import threading
import time
import uuid
from collections.abc import Iterable, Iterator
from contextvars import ContextVar
from typing import Any

from . import phi
from .identity import current_identity

try:  # POSIX inter-process lock
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows
    _fcntl = None  # type: ignore[assignment]
try:  # Windows inter-process lock
    import msvcrt as _msvcrt  # type: ignore[import-not-found]
except ImportError:
    _msvcrt = None  # type: ignore[assignment]

logger = logging.getLogger("proxmox_mcp.audit")

GENESIS = "genesis"
HMAC_CREDENTIAL = "audit-hmac.key"
MAC_DOMAIN = b"proxmox-mcp-audit-v1\0"
KID_DOMAIN = b"proxmox-mcp-audit-kid\0"
MIN_KEY_BYTES = 32
MAX_FIELD_CHARS = 1024
MAX_LINE_BYTES = 8192
_LINE_OVERHEAD = 512  # ts, mono, seq, ph, pid, eid, kid, mac
LOCK_TIMEOUT_S = 30.0
IS_WINDOWS = sys.platform == "win32"

_RESERVED = frozenset({"ts", "mono", "seq", "ph", "pid", "eid", "kid", "mac"})
_SECRET_FIELD_RE = re.compile(
    r"(?i)(passw|secret|token_value|^token$|access_token|refresh_token|id_token|authorization"
    r"|cookie|ticket|api_?key|private_?key|jwt|assertion|bearer|csrf|signature|hmac_key)"
)
# Identifier fields: a value that does not match is not an identifier, so it is hashed.
_IDENT_RES: dict[str, re.Pattern[str]] = {
    "tool": re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$"),
    "target": re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$"),
    "rpc": re.compile(r"^[A-Za-z][A-Za-z0-9_/]{0,63}$"),
    "method": re.compile(r"^[A-Z]{1,10}$"),
    "side": re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$"),
    "kind": re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$"),
    "mode": re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$"),
    "status": re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$"),
    "error": re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{0,127}$"),
    "user": re.compile(r"^[A-Za-z0-9._%+@!-]{1,254}$"),
    "svc": re.compile(r"^[A-Za-z0-9._%+@!-]{1,254}$"),
    "token_id": re.compile(r"^[A-Za-z0-9._+@!-]{1,200}$"),
    "ray": re.compile(r"^[A-Za-z0-9-]{1,64}$"),
    "jti": re.compile(r"^[A-Za-z0-9._:-]{1,128}$"),
    "request_id": re.compile(r"^[A-Za-z0-9._:-]{1,128}$"),
    "client": re.compile(r"^[0-9A-Fa-f.:]{2,45}$"),
}
_NO_PHI_CHECK = frozenset({"user", "svc", "token_id"})  # identities are logged by design
# Correlation ids are random (often UUIDs): pattern-checked, not secret-scrubbed.
_CORRELATION = frozenset({"jti", "request_id", "ray", "client"})
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# Path segments already passed outbound validation; "!" (UPID token ids) and "%" (encoded
# volume ids) are legitimate there and auditors need the real target (SOC 2 CC7.2 "what").
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.:@=+!%-]{0,128}$")
_ARGS_FIELDS = {"args": ("arg_keys", "args_sha256")}
# Kept when a line must shrink to fit MAX_LINE_BYTES.
_CORE = frozenset({
    "side", "kind", "user", "svc", "status", "deny", "error", "tool", "target", "rpc",
    "method", "path", "jti", "ray", "client", "request_id", "ms", "bytes", "args_sha256",
})

_SECRET_VALUE_RES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(-----END [A-Z0-9 ]+-----|$)", re.S),
     "[REDACTED key]"),
    (re.compile(r"PVEAPIToken=\S+"), "PVEAPIToken=[REDACTED]"),
    (re.compile(r"PVEAuthCookie=\S+"), "PVEAuthCookie=[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*"), "[REDACTED jwt]"),
    (re.compile(r"(?i)\b(passw\w*|secret|token|api[_-]?key|ticket|cookie|csrf\w*)(\s*[=:]\s*)\S+"),
     r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
     "[REDACTED uuid]"),
]

_LINE_MAC_RE = re.compile(rb'^(\{.*),"mac":"([0-9a-f]{64})"\}$')

_write_fd = os.write  # indirections so tests can simulate ENOSPC / short writes
_fsync = os.fsync


class AuditError(RuntimeError):
    """The audit line could not be written; the caller must not proceed."""


# ---- paths -------------------------------------------------------------------------


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


# Set when an audit log opens with a key. A plain sha256 of small arguments (a vmid, a
# refused PHI write) can be brute-forced from the log, so argument digests are keyed
# with the audit key when one exists; the line's ``kid`` names the key.
_args_key: bytes | None = None


def args_digest(args: Any) -> str:
    """Digest of tool or API arguments for audit lines: HMAC when keyed, else sha256."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    if _args_key is None:
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return hmac.new(_args_key, b"proxmox-mcp-args-v1\0" + canonical.encode("utf-8"), hashlib.sha256).hexdigest()


# ---- HMAC keys -----------------------------------------------------------------------


def parse_key(text: str | bytes) -> bytes:
    """A key from credential text: >= 64 hex digits, else >= 32 raw bytes."""
    raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    raw = raw.strip()
    if re.fullmatch(rb"(?:[0-9a-fA-F]{2}){32,}", raw):
        raw = bytes.fromhex(raw.decode("ascii"))
    if len(raw) < MIN_KEY_BYTES:
        raise ValueError("audit HMAC key is too short (need 32 bytes / 64 hex digits)")
    return raw


def key_id(key: bytes) -> str:
    return hashlib.sha256(KID_DOMAIN + key).hexdigest()[:16]


def compute_mac(key: bytes, body: bytes) -> str:
    return hmac.new(key, MAC_DOMAIN + body, hashlib.sha256).hexdigest()


def load_key_files(paths: Iterable[str | os.PathLike]) -> dict[str, bytes]:
    """{kid: key} from auditor-held key files (escrowed copies of audit-hmac.key)."""
    keys: dict[str, bytes] = {}
    for path in paths:
        with open(path, "rb") as fh:
            key = parse_key(fh.read(64 * 1024))
        keys[key_id(key)] = key
    return keys


def _hmac_mode() -> str:
    mode = (os.environ.get("MCP_AUDIT_HMAC") or "auto").strip().lower()
    if mode not in ("auto", "required", "off"):
        raise AuditError("MCP_AUDIT_HMAC must be auto, required or off")
    return mode


def _load_configured_key(mode: str) -> bytes | None:
    """The broker's HMAC key, or None. A present-but-broken key fails closed."""
    if mode == "off":
        return None
    from . import credentials  # lazy: keeps audit importable without credential config

    try:
        path = credentials.credential_path(HMAC_CREDENTIAL)
    except credentials.CredentialError:
        path = None  # no credential directory configured
    if path is None or not os.path.lexists(path):
        if mode == "required":
            raise AuditError("audit HMAC key required but not present")
        return None
    try:
        text = credentials.read_credential(HMAC_CREDENTIAL)
        try:
            return parse_key(text)
        finally:
            del text
    except (credentials.CredentialError, ValueError):
        raise AuditError("audit HMAC key is present but unusable") from None


# ---- content sanitizing --------------------------------------------------------------


def _short_hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def _scrub_text(text: str) -> str:
    for pattern, repl in _SECRET_VALUE_RES:
        text = pattern.sub(repl, text)
    return phi.redact_phi(text)


def _cap(text: str, limit: int = MAX_FIELD_CHARS) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def _safe_token(
    value: str, pattern: re.Pattern[str], *, phi_check: bool = True, scrub: bool = True
) -> str:
    """value when it is a clean identifier; else a redaction marker or a short hash."""
    if phi_check:
        kind = phi.find_phi_in_text(value)
        if kind:
            return f"[REDACTED {kind}]"
    if pattern.match(value) and (not scrub or _scrub_text(value) == value):
        return value
    return _short_hash(value)


def _safe_keys(keys: Iterable[Any]) -> list[str]:
    return sorted(_safe_token(str(k), _KEY_RE) for k in keys)


def _safe_path(path: str) -> str:
    parts = path.split("?", 1)[0].split("/")
    return _cap("/".join(_safe_token(p, _SEGMENT_RE) if p else p for p in parts))


def _clean(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "[nested]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _cap(_scrub_text(value))
    if isinstance(value, dict):
        return {"keys": _safe_keys(value), "sha256": args_digest(value)}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_clean(v, depth + 1) for v in list(value)[:50]]
    return _clean(str(value), depth)


def build_fields(fields: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in fields.items():
        key = str(key)
        if key in _RESERVED or _SECRET_FIELD_RE.search(key):
            continue
        if not _KEY_RE.match(key):
            continue  # a field name is ours, never data; drop anything odd
        if isinstance(value, dict):
            keys_name, hash_name = _ARGS_FIELDS.get(key, (f"{key}_keys", f"{key}_sha256"))
            out[keys_name] = _safe_keys(value)
            out[hash_name] = args_digest(value)
            continue
        if key == "args":  # non-dict args: hash only
            out["args_sha256"] = args_digest(value)
            continue
        if key == "arg_keys" and isinstance(value, (list, tuple)):
            out[key] = _safe_keys(value)
            continue
        if key == "path" and isinstance(value, str):
            out[key] = _safe_path(value)
            continue
        pattern = _IDENT_RES.get(key)
        if pattern is not None and isinstance(value, str):
            out[key] = _safe_token(
                value, pattern, phi_check=key not in _NO_PHI_CHECK, scrub=key not in _CORRELATION
            )
            continue
        out[key] = _clean(value)
    return out


def _dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True, default=str)


def _fit(fields: dict[str, Any], budget: int) -> dict[str, Any]:
    """Shrink fields to budget bytes: drop the largest non-core values, then cap strings."""
    if len(_dumps(fields)) <= budget:
        return fields
    fields = dict(fields)
    sizes = sorted(
        ((len(_dumps(v)), k) for k, v in fields.items() if k not in _CORE), reverse=True
    )
    for size, key in sizes:
        if len(_dumps(fields)) <= budget:
            return fields
        fields[key] = {"dropped": size, "sha256": hashlib.sha256(_dumps(fields[key]).encode()).hexdigest()[:16]}
    limit = 256
    while len(_dumps(fields)) > budget and limit >= 16:
        fields = {k: (_cap(v, limit) if isinstance(v, str) else v) for k, v in fields.items()}
        limit //= 2
    return fields


# ---- correlation context -------------------------------------------------------------

_context: ContextVar[dict[str, Any] | None] = ContextVar("proxmox_mcp_audit_context", default=None)


@contextlib.contextmanager
def bind(**fields: Any) -> Iterator[None]:
    """Add correlation fields (jti, svc, request_id, client) to every line in this context."""
    merged = {**(_context.get() or {}), **fields}
    token = _context.set(merged)
    try:
        yield
    finally:
        _context.reset(token)


def _with_context(fields: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    ident = current_identity.get()
    if ident is not None:
        merged["user"] = ident.subject
        if ident.ray_id:
            merged["ray"] = ident.ray_id
    merged.update(_context.get() or {})
    merged.update(fields)
    return merged


# ---- health --------------------------------------------------------------------------

_health_lock = threading.Lock()
_health: dict[str, Any] = {"ok": True, "failures": 0, "last_error": None, "last_error_ts": None}


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _record_failure(reason: str) -> None:
    with _health_lock:
        _health.update(ok=False, last_error=reason, last_error_ts=_now_iso())
        _health["failures"] += 1
    logger.critical("audit write failed: %s (tool calls are denied until it recovers)", reason)


def _record_ok() -> None:
    if not _health["ok"]:
        with _health_lock:
            _health["ok"] = True
        logger.warning("audit write recovered after %d failure(s)", _health["failures"])


def health() -> dict[str, Any]:
    """Audit sink state for /healthz and monitoring (no paths, no secrets)."""
    with _health_lock:
        return dict(_health)


def _reason(exc: BaseException) -> str:
    if isinstance(exc, OSError) and exc.errno:
        return _errno.errorcode.get(exc.errno, f"errno {exc.errno}")
    if isinstance(exc, AuditError):
        return str(exc)
    return type(exc).__name__


# ---- reading the chain head ------------------------------------------------------------


def _parse(raw: bytes) -> dict[str, Any] | None:
    try:
        rec = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(rec, dict):
        return None
    seq = rec.get("seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or not isinstance(rec.get("ph"), str):
        return None
    return rec


def _head_of(lines: list[bytes]) -> tuple[str, int | None, bool] | None:
    """(hash of last line, next seq or None, keyed) from the tail lines of a file."""
    lines = [ln for ln in lines if ln]
    if not lines:
        return None
    torn = 0
    for raw in reversed(lines):
        rec = _parse(raw)
        if rec is not None:
            return line_hash(lines[-1]), rec["seq"] + torn + 1, "mac" in rec
        torn += 1
    return line_hash(lines[-1]), None, False


def _tail_fd(fd: int, size: int, nbytes: int) -> list[bytes]:
    start = max(0, size - nbytes)
    os.lseek(fd, start, os.SEEK_SET)
    data = b""
    while len(data) < size - start:
        chunk = os.read(fd, size - start - len(data))
        if not chunk:
            break
        data += chunk
    lines = data.split(b"\n")
    if start > 0:
        lines = lines[1:]  # first fragment may be a partial line
    return [ln.rstrip(b"\r") for ln in lines]


def _tail_path(path: str, nbytes: int = 4 * MAX_LINE_BYTES) -> list[bytes]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return []
    try:
        return _tail_fd(fd, os.fstat(fd).st_size, nbytes)
    finally:
        os.close(fd)


def _siblings(path: str) -> list[str]:
    directory = os.path.dirname(path) or "."
    stem = os.path.splitext(os.path.basename(path))[0]
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    return [
        os.path.join(directory, n) for n in names
        if n.startswith(stem + "-") and n.endswith(".jsonl")
    ]


def _sibling_head(path: str) -> tuple[str, int, bool] | None:
    """Head of the shipped sibling with the highest seq (mtime breaks ties)."""
    best: tuple[int, float, tuple[str, int, bool]] | None = None
    for sibling in _siblings(path):
        head = _head_of(_tail_path(sibling))
        if head is None or head[1] is None:
            continue
        try:
            mtime = os.path.getmtime(sibling)
        except OSError:
            mtime = 0.0
        candidate = (head[1], mtime, (head[0], head[1], head[2]))
        if best is None or candidate[:2] > best[:2]:
            best = candidate
    return best[2] if best else None


# ---- writer ----------------------------------------------------------------------------


@contextlib.contextmanager
def _interprocess_lock(path: str) -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path + ".lock", flags, 0o600)
    try:
        if _fcntl is not None:
            _fcntl.flock(fd, _fcntl.LOCK_EX)
        elif _msvcrt is not None:  # pragma: no cover - Windows
            deadline = time.monotonic() + LOCK_TIMEOUT_S
            while True:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    _msvcrt.locking(fd, _msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.01)
        try:
            yield
        finally:
            if _fcntl is not None:
                _fcntl.flock(fd, _fcntl.LOCK_UN)
            elif _msvcrt is not None:  # pragma: no cover - Windows
                os.lseek(fd, 0, os.SEEK_SET)
                _msvcrt.locking(fd, _msvcrt.LK_UNLCK, 1)
    finally:
        os.close(fd)


class AuditLog:
    """Open, read head, append one line, fsync and close per event (see module doc)."""

    def __init__(self, path: str, key: bytes | None = None, hmac_mode: str = "auto") -> None:
        global _args_key
        self.path = path
        self._key = key
        if key is not None:
            _args_key = hashlib.sha256(b"proxmox-mcp-args-key-v1\0" + key).digest()
        self._kid = key_id(key) if key is not None else None
        self._hmac_mode = hmac_mode
        self._lock = threading.Lock()
        self._prev_hash: str | None = None
        self._seq: int | None = None
        self._started = False
        self._start_lock = threading.Lock()

    @property
    def kid(self) -> str | None:
        return self._kid

    def _head(self, fd: int, size: int) -> tuple[str, int, bool, bool]:
        """(prev hash, seq, prev keyed, needs newline) for the file open on fd."""
        if size:
            lines = _tail_fd(fd, size, 4 * MAX_LINE_BYTES)
            os.lseek(fd, size - 1, os.SEEK_SET)
            needs_newline = os.read(fd, 1) != b"\n"
            head = _head_of(lines)
            if head is not None:
                seq = head[1] if head[1] is not None else (self._seq or 0)
                return head[0], seq, head[2], needs_newline
        candidates: list[tuple[int, str, bool]] = []
        if self._prev_hash is not None and self._seq is not None:
            candidates.append((self._seq, self._prev_hash, self._key is not None))
        sibling = _sibling_head(self.path)
        if sibling is not None:
            candidates.append((sibling[1], sibling[0], sibling[2]))
        if not candidates:
            return GENESIS, 0, False, False
        seq, prev, keyed = max(candidates, key=lambda c: c[0])
        return prev, seq, keyed, False

    def _encode(self, prev_hash: str, seq: int, fields: dict[str, Any]) -> bytes:
        record: dict[str, Any] = {
            "ts": _now_iso(),
            "mono": round(time.monotonic(), 3),
            "seq": seq,
            "ph": prev_hash,
            "pid": os.getpid(),
            "eid": uuid.uuid4().hex,
            **fields,
        }
        if self._key is None:
            return _dumps(record).encode("ascii")
        record["kid"] = self._kid
        body = _dumps(record).encode("ascii")
        mac = compute_mac(self._key, body)
        return body[:-1] + b',"mac":"' + mac.encode("ascii") + b'"}'

    def _write_locked(self, fields: dict[str, Any]) -> bytes:
        directory = os.path.dirname(self.path) or "."
        if not os.path.isdir(directory):
            os.makedirs(directory, mode=0o700, exist_ok=True)
        with _interprocess_lock(self.path):
            existed = os.path.lexists(self.path)
            flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
            flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            try:
                st = os.fstat(fd)
                if not IS_WINDOWS and st.st_mode & 0o077:
                    os.fchmod(fd, 0o600)
                prev_hash, seq, prev_keyed, needs_newline = self._head(fd, st.st_size)
                if prev_keyed and self._key is None and self._hmac_mode != "off":
                    raise AuditError("audit chain is keyed but no HMAC key is loaded")
                line = self._encode(prev_hash, seq, fields)
                data = (b"\n" if needs_newline else b"") + line + b"\n"
                if len(line) > MAX_LINE_BYTES:
                    raise AuditError("audit line over MAX_LINE_BYTES")
                # One write per line (O_APPEND atomic); loop only if the OS returns short.
                view = memoryview(data)
                while view:
                    written = _write_fd(fd, view)
                    if written <= 0:
                        raise OSError(_errno.EIO, "short write")
                    view = view[written:]
                _fsync(fd)
            finally:
                os.close(fd)
            if not existed and not IS_WINDOWS:
                dfd = os.open(directory, os.O_RDONLY)
                try:
                    _fsync(dfd)
                finally:
                    os.close(dfd)
        self._prev_hash = line_hash(line)
        self._seq = seq + 1
        return line

    def write(self, fields: dict[str, Any]) -> str:
        record_fields = _fit(build_fields(fields), MAX_LINE_BYTES - _LINE_OVERHEAD)
        with self._lock:
            try:
                line = self._write_locked(record_fields)
            except Exception as exc:
                _record_failure(_reason(exc))
                raise AuditError("audit log unavailable") from None
        _record_ok()
        text = line.decode("ascii")
        logger.info(text)
        return text

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
            try:
                mode = _hmac_mode()
                key = _load_configured_key(mode)
            except AuditError as exc:
                _record_failure(str(exc))
                raise
            _log = AuditLog(path, key, mode)
            del key
        log = _log
    with log._start_lock:
        if not log._started:
            log.write(
                {
                    "side": "broker",
                    "kind": "start",
                    "version": _version(),
                    "catalog_sha256": _catalog_hash(),
                    "host": socket.gethostname(),
                    "hmac": log.kid or "none",
                    **_config_fields(),
                }
            )
            log._started = True
    return log


def _config_fields() -> dict[str, Any]:
    """Role, dangerous flags, TLS mode and config hash for the start event (SOC 2 CC8.1)."""
    try:
        from . import config

        return dict(config.audit_start_fields())
    except Exception:  # noqa: BLE001 - the start event must never fail on this
        return {}


def start() -> None:
    """Open the log and write the start event (version + catalog hash). Idempotent."""
    _get_log()


def audit_event(**fields: Any) -> None:
    """Append one chained line. Raises AuditError if it cannot be written (fail closed)."""
    log = _get_log()
    log.write(_with_context(fields))


def reset_for_tests() -> None:
    global _log
    with _lock:
        if _log is not None:
            _log.close()
        _log = None
    with _health_lock:
        _health.update(ok=True, failures=0, last_error=None, last_error_ts=None)


# ---- verification --------------------------------------------------------------------

_MAX_REPORTED = 100


class Verifier:
    """Streams lines (oldest first, across files) and collects an auditor summary."""

    def __init__(
        self,
        prev_hash: str | None = None,
        *,
        keys: dict[str, bytes] | None = None,
        require_mac: bool = False,
        anchor: tuple[int, str] | None = None,
    ) -> None:
        self.prev_hash = prev_hash
        self.keys = dict(keys or {})
        self.require_mac = require_mac
        self.anchor = anchor
        self._anchor_hash: str | None = None
        self.prev_seq: int | None = None
        self.skipped = 0
        self.keyed_seen = False
        self.lines = self.breaks = 0
        self.problems: list[dict[str, Any]] = []
        self.gaps: list[dict[str, Any]] = []
        self.first_ts = self.last_ts = None
        self.first_seq: int | None = None
        self.last_seq: int | None = None
        self.mac = {"with_mac": 0, "without_mac": 0, "verified": 0, "invalid": 0, "unverified": 0}
        self.kids: set[str] = set()
        self.files: list[dict[str, Any]] = []

    def _check_mac(self, raw: bytes, rec: dict[str, Any], reasons: list[str]) -> None:
        if "mac" not in rec:
            self.mac["without_mac"] += 1
            if self.keyed_seen or self.require_mac:
                reasons.append("mac_missing")
            return
        self.keyed_seen = True
        self.mac["with_mac"] += 1
        kid = rec.get("kid")
        if isinstance(kid, str):
            self.kids.add(kid)
        m = _LINE_MAC_RE.match(raw)
        if m is None or rec.get("mac") != m.group(2).decode("ascii") or not isinstance(kid, str):
            self.mac["invalid"] += 1
            reasons.append("mac_invalid")
            return
        key = self.keys.get(kid)
        if key is None:
            self.mac["unverified"] += 1
            if self.require_mac:
                reasons.append("mac_unverified")
            return
        if hmac.compare_digest(compute_mac(key, m.group(1) + b"}"), m.group(2).decode("ascii")):
            self.mac["verified"] += 1
        else:
            self.mac["invalid"] += 1
            reasons.append("mac_invalid")

    def feed(self, raw: bytes, path: str = "-", lineno: int = 0) -> list[str]:
        raw = raw.rstrip(b"\r\n")
        if not raw:
            return []
        self.lines += 1
        reasons: list[str] = []
        rec = _parse(raw)
        if rec is None:
            reasons.append("unparseable")
            self.skipped += 1
        else:
            ph, seq = rec["ph"], rec["seq"]
            if self.prev_hash is not None and ph != self.prev_hash:
                reasons.append("ph_mismatch")
            if self.prev_seq is not None:
                expected = self.prev_seq + 1 + self.skipped
                if seq != expected:
                    reasons.append("seq_gap")
                    if len(self.gaps) < _MAX_REPORTED:
                        self.gaps.append({"path": path, "line": lineno, "expected": expected, "got": seq})
            elif ph == GENESIS and seq != 0:
                reasons.append("seq_gap")
            self._check_mac(raw, rec, reasons)
            ts = rec.get("ts") if isinstance(rec.get("ts"), str) else None
            if self.first_ts is None:
                self.first_ts = ts
            self.last_ts = ts or self.last_ts
            if self.first_seq is None:
                self.first_seq = seq
            self.last_seq = seq
            self.prev_seq = seq
            self.skipped = 0
            if self.anchor is not None and seq == self.anchor[0]:
                self._anchor_hash = line_hash(raw)
        self.prev_hash = line_hash(raw)
        if reasons:
            self.breaks += 1
            if len(self.problems) < _MAX_REPORTED:
                seq_value = rec.get("seq") if rec else None
                self.problems.append({"path": path, "line": lineno, "seq": seq_value, "reasons": reasons})
        return reasons

    def feed_file(self, path: str | os.PathLike) -> None:
        name = os.fspath(path)
        before = (self.lines, self.breaks)
        first_seq = first_ts = None
        with open(name, "rb") as fh:
            for lineno, raw in enumerate(fh, 1):
                self.feed(raw, name, lineno)
                if first_seq is None and self.last_seq is not None and self.lines > before[0]:
                    first_seq, first_ts = self.last_seq, self.last_ts
        self.files.append({
            "path": name,
            "lines": self.lines - before[0],
            "breaks": self.breaks - before[1],
            "first_seq": first_seq if self.lines > before[0] else None,
            "last_seq": self.last_seq if self.lines > before[0] else None,
            "first_ts": first_ts,
            "last_ts": self.last_ts if self.lines > before[0] else None,
        })

    def _mac_status(self) -> str:
        m = self.mac
        if m["with_mac"] == 0:
            return "absent"
        if m["invalid"]:
            return "invalid"
        if m["unverified"]:
            return "unverified"
        if m["without_mac"]:
            return "partial"
        return "verified"

    def summary(self) -> dict[str, Any]:
        breaks = self.breaks
        problems = list(self.problems)
        anchor_out = None
        if self.anchor is not None:
            ok = self._anchor_hash is not None and self._anchor_hash == self.anchor[1]
            anchor_out = {"seq": self.anchor[0], "hash": self.anchor[1], "ok": ok}
            if not ok:
                breaks += 1
                reason = "anchor_missing" if self._anchor_hash is None else "anchor_mismatch"
                problems.append({"path": None, "line": None, "seq": self.anchor[0], "reasons": [reason]})
        if self.require_mac and self._mac_status() != "verified" and breaks == 0:
            breaks += 1
            problems.append({"path": None, "line": None, "seq": None, "reasons": ["mac_not_verified"]})
        return {
            "ok": breaks == 0,
            "files": self.files,
            "lines": self.lines,
            "breaks": breaks,
            "gaps": self.gaps,
            "problems": problems,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "last_hash": self.prev_hash,
            "mac": {
                "status": self._mac_status(),
                "lines_with_mac": self.mac["with_mac"],
                "lines_without_mac": self.mac["without_mac"],
                "verified": self.mac["verified"],
                "invalid": self.mac["invalid"],
                "unverified": self.mac["unverified"],
                "kids": sorted(self.kids),
                "require_mac": self.require_mac,
            },
            "anchor": anchor_out,
        }


def verify_lines(lines: Iterable[bytes], prev_hash: str | None = None) -> tuple[int, int, str | None]:
    """(lines, breaks, last_hash). The first line is the anchor when prev_hash is None.

    Unkeyed check (ph + seq + downgrade). Use verify_files for macs and a summary.
    """
    v = Verifier(prev_hash)
    for raw in lines:
        v.feed(raw)
    return v.lines, v.breaks, v.prev_hash


def verify_chain(paths: str | os.PathLike | Iterable[str | os.PathLike], prev_hash: str | None = None) -> int:
    """Number of chain breaks across one file or several files in order (0 = intact)."""
    if isinstance(paths, (str, os.PathLike)):
        paths = [paths]
    v = Verifier(prev_hash)
    for path in paths:
        v.feed_file(path)
    return v.breaks


def verify_files(
    paths: Iterable[str | os.PathLike],
    *,
    keys: dict[str, bytes] | None = None,
    require_mac: bool = False,
    anchor: tuple[int, str] | None = None,
    prev_hash: str | None = None,
) -> dict[str, Any]:
    """Auditor summary over files in order (oldest first). Raises OSError if unreadable."""
    v = Verifier(prev_hash, keys=keys, require_mac=require_mac, anchor=anchor)
    for path in paths:
        v.feed_file(path)
    return v.summary()


def files_in_dir(directory: str, stem: str = "audit") -> list[str]:
    """audit-*.jsonl ordered by their first seq (then name), then the live audit.jsonl."""
    live = os.path.join(directory, stem + ".jsonl")
    shipped = _siblings(live)

    def first_seq(path: str) -> tuple[float, str]:
        try:
            with open(path, "rb") as fh:
                for raw in fh:
                    rec = _parse(raw.rstrip(b"\r\n"))
                    if rec is not None:
                        return float(rec["seq"]), os.path.basename(path)
        except OSError:
            pass
        return float("inf"), os.path.basename(path)

    ordered = sorted(shipped, key=first_seq)
    if os.path.isfile(live):
        ordered.append(live)
    return ordered


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:  # never sys.exit from inside main()
        raise _UsageError(message)


def _parse_anchor(text: str) -> tuple[int, str]:
    m = re.fullmatch(r"(\d+):([0-9a-f]{64})", text.strip())
    if not m:
        raise _UsageError("--anchor must be SEQ:SHA256HEX")
    return int(m.group(1)), m.group(2)


def _emit(doc: dict[str, Any]) -> None:
    print(json.dumps(doc, indent=2))


def main(argv: list[str] | None = None) -> int:
    """``proxmox-mcp-audit-verify`` — print a JSON summary for auditors.

    Exit codes (stable): 0 intact; 1 integrity failure (breaks, seq gaps, bad or
    missing macs, anchor not found, --require-mac not satisfied); 2 usage or I/O
    error (nothing was verified).
    """
    parser = _Parser(prog="proxmox-mcp-audit-verify", add_help=True)
    parser.add_argument("files", nargs="*", help="files oldest first (default: --dir of MCP_AUDIT_LOG)")
    parser.add_argument("--dir", help="verify every audit-*.jsonl plus audit.jsonl in DIR, ordered by seq")
    parser.add_argument("--key-file", action="append", default=[], help="HMAC key copy (repeatable)")
    parser.add_argument("--no-credential", action="store_true",
                        help="do not try the broker's audit-hmac.key credential")
    parser.add_argument("--require-mac", action="store_true", help="every line must carry a verified mac")
    parser.add_argument("--anchor", help="SEQ:HASH recorded at the last WORM upload (truncation check)")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
        anchor = _parse_anchor(args.anchor) if args.anchor else None
        if args.files:
            files = list(args.files)
        else:
            live = configured_path()
            directory = args.dir or os.path.dirname(live) or "."
            if not os.path.isdir(directory):
                raise _UsageError("audit directory not found")
            stem = os.path.splitext(os.path.basename(live))[0] if not args.dir else "audit"
            files = files_in_dir(directory, stem)
            if not files:
                raise _UsageError("no audit files found")
        keys = load_key_files(args.key_file)
        if not args.no_credential:
            with contextlib.suppress(Exception):
                key = _load_configured_key("auto")
                if key is not None:
                    keys.setdefault(key_id(key), key)
                del key
        summary = verify_files(files, keys=keys, require_mac=args.require_mac, anchor=anchor)
    except _UsageError as exc:
        _emit({"ok": False, "error": f"usage: {exc}", "exit": 2})
        return 2
    except (OSError, ValueError) as exc:
        _emit({"ok": False, "error": f"cannot read input ({type(exc).__name__})", "exit": 2})
        return 2
    code = 0 if summary["ok"] else 1
    summary["exit"] = code
    _emit(summary)
    return code


if __name__ == "__main__":
    sys.exit(main())
