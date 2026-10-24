"""Who may use this MCP server, in which mode, and as which Proxmox identity.

The enrollment file is the only place that grants access. It is a JSON document,
read from ``MCP_ENROLLMENT_FILE`` or, by default, ``$CREDENTIALS_DIRECTORY/enrollment.json``
(a systemd credential) or ``%BROKER_CREDENTIALS_DIR%\\enrollment.json`` (Windows broker)::

    {
      "users": {
        "alice@example.com": {"mode": "rw", "proxmox_userid": "alice@pve",
                              "token_credential": "pve-token-alice"}
      },
      "services": {
        "<access service token client id>": {"mode": "ro", "proxmox_userid": "svc-ci@pve",
                                             "token_credential": "pve-token-svc-ci"}
      }
    }

Rules (fail closed):
- Validation is strict. Unknown keys, unknown modes, malformed emails, ``root@pam`` and
  bad credential names make the whole file invalid, and an invalid file grants nobody.
- A missing file grants nobody. A symlink, a non-regular file or a file over 1 MB is invalid.
- The file is re-read on every lookup and the parse is cached by content hash, so a
  revocation takes effect on the next call (no stat-based staleness).
- Emails must be ASCII (checked before lowercasing; see _email_key) and are compared
  lowercased. Service identities (Access service tokens) need their own
  entry under ``services`` keyed by their subject; they never match a user entry.
- The stdio (``local``) identity is a developer on the host. It gets a synthetic enrollment
  whose mode comes from ``MCP_LOCAL_MODE`` (default ``ro``) and an empty ``token_credential``,
  which tells the client to use the ``PROXMOX_TOKEN_*`` environment instead.

``token_credential`` is the *name* of a systemd credential file that holds ``tokenid=secret``
for that person's privilege-separated Proxmox API token. The secret itself never appears here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import stat
import threading
from dataclasses import dataclass
from typing import Any, Literal, get_args

from .identity import Identity

log = logging.getLogger(__name__)

Mode = Literal["ro", "operator", "rw"]
MODES: tuple[str, ...] = get_args(Mode)

_EMAIL_RE = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$")
_SERVICE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_USERID_RE = re.compile(r"^[A-Za-z0-9._-]+@(pve|pam|[A-Za-z0-9._-]+)$")
_CREDENTIAL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

_ENTRY_KEYS = frozenset({"mode", "proxmox_userid", "token_credential"})
_TOP_KEYS = frozenset({"users", "services"})


@dataclass(frozen=True)
class Enrollment:
    subject: str
    mode: Mode
    proxmox_userid: str
    # Name of the systemd credential holding "tokenid=secret". Empty only for the local identity.
    token_credential: str


class EnrollmentError(ValueError):
    """The enrollment file is not valid. Nobody is enrolled until it is fixed."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise EnrollmentError(f"duplicate key {key!r}")
        out[key] = value
    return out


def _parse_entry(subject: str, raw: Any) -> Enrollment:
    if not isinstance(raw, dict):
        raise EnrollmentError(f"{subject}: entry must be an object")
    keys = set(raw)
    if keys != _ENTRY_KEYS:
        extra = sorted(keys - _ENTRY_KEYS)
        missing = sorted(_ENTRY_KEYS - keys)
        raise EnrollmentError(f"{subject}: unknown keys {extra}, missing keys {missing}")

    mode = raw["mode"]
    if mode not in MODES:
        raise EnrollmentError(f"{subject}: mode must be one of {list(MODES)}")

    userid = raw["proxmox_userid"]
    if not isinstance(userid, str) or len(userid) > 128 or not _USERID_RE.fullmatch(userid):
        raise EnrollmentError(f"{subject}: proxmox_userid must look like user@realm")
    if userid.lower() == "root@pam":
        raise EnrollmentError(f"{subject}: root@pam may not be enrolled; use a dedicated user")

    cred = raw["token_credential"]
    if not isinstance(cred, str) or not _CREDENTIAL_RE.fullmatch(cred) or cred.startswith("."):
        raise EnrollmentError(f"{subject}: token_credential must match [A-Za-z0-9_.-]{{1,64}}")

    return Enrollment(subject=subject, mode=mode, proxmox_userid=userid, token_credential=cred)


def parse_enrollments(doc: Any) -> dict[str, Enrollment]:
    """Validate a decoded enrollment document. Keys of the result are the lookup subjects."""
    if not isinstance(doc, dict):
        raise EnrollmentError("top level must be an object")
    unknown = set(doc) - _TOP_KEYS
    if unknown:
        raise EnrollmentError(f"unknown top-level keys {sorted(unknown)}")
    if "users" not in doc:
        raise EnrollmentError('missing "users"')

    out: dict[str, Enrollment] = {}
    users = doc["users"]
    if not isinstance(users, dict):
        raise EnrollmentError('"users" must be an object')
    for raw_email, entry in users.items():
        email = _email_key(raw_email.strip()) if isinstance(raw_email, str) else None
        if email is None:
            raise EnrollmentError(f"not an email address: {raw_email!r}")
        if len(email) > 254 or not _EMAIL_RE.fullmatch(email):
            raise EnrollmentError(f"not an email address: {raw_email!r}")
        if email in out:
            raise EnrollmentError(f"{email} is enrolled twice")
        out[email] = _parse_entry(email, entry)

    services = doc.get("services", {})
    if not isinstance(services, dict):
        raise EnrollmentError('"services" must be an object')
    for subject, entry in services.items():
        if not isinstance(subject, str) or not _SERVICE_RE.fullmatch(subject):
            raise EnrollmentError(f"bad service subject {subject!r}")
        key = _service_key(subject)
        if key in out:
            raise EnrollmentError(f"service {subject} is enrolled twice")
        out[key] = _parse_entry(subject, entry)
    _require_one_person_one_key(out)
    return out


def _require_one_person_one_key(table: dict[str, Enrollment]) -> None:
    """MCP-STD-01 "one person, one key": no two subjects (users or services) may share a
    token_credential or a proxmox_userid, or Proxmox's task log could not name the person.
    Compared case-insensitively (Windows credential files are case-insensitive; a userid
    differing only in case is too close to call). A violation invalidates the whole file.
    """
    seen_cred: dict[str, str] = {}
    seen_user: dict[str, str] = {}
    for entry in table.values():
        cred = entry.token_credential.lower()
        if cred in seen_cred:
            raise EnrollmentError(
                f"{entry.subject} and {seen_cred[cred]} share token_credential {entry.token_credential}"
            )
        seen_cred[cred] = entry.subject
        userid = entry.proxmox_userid.lower()
        if userid in seen_user:
            raise EnrollmentError(
                f"{entry.subject} and {seen_user[userid]} share proxmox_userid {entry.proxmox_userid}"
            )
        seen_user[userid] = entry.subject


def _email_key(value: str) -> str | None:
    """Lowercased lookup key for an email, or None when it is not a plain ASCII address.

    ASCII is checked BEFORE lowercasing: str.lower() maps some non-ASCII code points onto
    ASCII (U+212A KELVIN SIGN -> "k"), so lowercasing first would let "\\u212aate@..."
    match kate@... (H2 finding). No stripping either: a signed identity is matched exactly.
    """
    if not value.isascii():
        return None
    key = value.lower()
    return key if len(key) <= 254 and _EMAIL_RE.fullmatch(key) else None


def _service_key(subject: str) -> str:
    # Separate namespace: a service subject can never collide with a user email.
    return f"service:{subject}"


def default_path() -> str | None:
    path = os.environ.get("MCP_ENROLLMENT_FILE")
    if path:
        return path
    # systemd (Linux) first, then the Windows broker's credential directory.
    for var in ("CREDENTIALS_DIRECTORY", "BROKER_CREDENTIALS_DIR"):
        creds = os.environ.get(var)
        if creds:
            return os.path.join(creds, "enrollment.json")
    return None


MAX_FILE_BYTES = 1_000_000

_cache_lock = threading.Lock()
# path -> (sha256 of the bytes, parsed table). Keyed by CONTENT, not by stat: a same-size
# edit inside one mtime tick (rw -> ro, same inode) must not be served from cache, or a
# revocation is missed (H2 finding).
_cache: dict[str, tuple[bytes, dict[str, Enrollment]]] = {}


def _read_file(path: str) -> bytes | None:
    """The file's bytes, or None when it does not exist.

    Refuses a symlink as the final component (O_NOFOLLOW where the OS has it, plus an lstat
    check), anything but a regular file, and anything over MAX_FILE_BYTES, checked on the
    opened descriptor so a swap between check and read cannot change what is measured.
    """
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(lst.st_mode):
        raise EnrollmentError("enrollment file must not be a symlink")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise EnrollmentError(f"cannot open enrollment file: {exc.strerror}") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise EnrollmentError("enrollment file must be a regular file")
        if st.st_size > MAX_FILE_BYTES:
            raise EnrollmentError("enrollment file is larger than 1 MB")
        chunks = []
        remaining = MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE_BYTES:
        raise EnrollmentError("enrollment file is larger than 1 MB")
    return data


def load_enrollments(path: str | None = None) -> dict[str, Enrollment]:
    """Read and validate the enrollment file. The file is read on every call (it is small)
    and the parse is cached by content hash, so every change is seen immediately.

    Missing file (or no path configured) -> {} (nobody enrolled).
    Invalid, symlinked, non-regular or oversize file -> EnrollmentError.
    """
    path = path or default_path()
    if not path:
        return {}
    data = _read_file(path)
    if data is None:
        return {}
    digest = hashlib.sha256(data).digest()
    with _cache_lock:
        hit = _cache.get(path)
        if hit and hmac.compare_digest(hit[0], digest):
            return hit[1]
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except UnicodeDecodeError:
        raise EnrollmentError("enrollment file is not UTF-8") from None
    except json.JSONDecodeError as exc:
        raise EnrollmentError(f"not valid JSON: {exc.msg} at line {exc.lineno}") from None
    except RecursionError:
        raise EnrollmentError("enrollment file is nested too deeply") from None
    result = parse_enrollments(doc)
    with _cache_lock:
        _cache[path] = (digest, result)
    return result


def _local_enrollment(identity: Identity) -> Enrollment:
    mode = os.environ.get("MCP_LOCAL_MODE", "ro").strip().lower() or "ro"
    if mode not in MODES:
        log.warning("MCP_LOCAL_MODE=%r is not one of %s; using ro", mode, MODES)
        mode = "ro"
    return Enrollment(
        subject=identity.subject,
        mode=mode,  # type: ignore[arg-type]
        proxmox_userid=os.environ.get("PROXMOX_USER", ""),
        token_credential="",
    )


def enrollment_for(identity: Identity) -> Enrollment:
    """The enrollment of this caller. Raises PermissionError("not enrolled") otherwise."""
    if identity.kind == "local":
        return _local_enrollment(identity)
    try:
        table = load_enrollments()
    except (OSError, EnrollmentError) as exc:
        # Fail closed and say why in the server log (never to the caller).
        log.error("enrollment file unusable, denying everyone: %s", exc)
        raise PermissionError("not enrolled") from None

    if identity.kind == "user":
        raw = identity.email or identity.subject or ""
        key = _email_key(raw) if isinstance(raw, str) else None
        found = table.get(key) if key else None
    elif identity.kind == "service":
        found = table.get(_service_key(identity.subject))
    else:
        found = None
    if found is None:
        raise PermissionError("not enrolled")
    return found
