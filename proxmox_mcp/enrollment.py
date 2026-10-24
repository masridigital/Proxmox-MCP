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
- A missing file grants nobody.
- Emails are compared lowercased. Service identities (Access service tokens) need their own
  entry under ``services`` keyed by their subject; they never match a user entry.
- The stdio (``local``) identity is a developer on the host. It gets a synthetic enrollment
  whose mode comes from ``MCP_LOCAL_MODE`` (default ``ro``) and an empty ``token_credential``,
  which tells the client to use the ``PROXMOX_TOKEN_*`` environment instead.

``token_credential`` is the *name* of a systemd credential file that holds ``tokenid=secret``
for that person's privilege-separated Proxmox API token. The secret itself never appears here.
"""

from __future__ import annotations

import json
import logging
import os
import re
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
        email = raw_email.strip().lower() if isinstance(raw_email, str) else ""
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
    return out


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


_cache_lock = threading.Lock()
_cache: dict[str, tuple[tuple[int, int, int], dict[str, Enrollment]]] = {}


def load_enrollments(path: str | None = None) -> dict[str, Enrollment]:
    """Read and validate the enrollment file. Cached; reloaded when the file changes.

    Missing file (or no path configured) -> {} (nobody enrolled).
    Invalid file -> EnrollmentError.
    """
    path = path or default_path()
    if not path:
        return {}
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return {}
    stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
    with _cache_lock:
        hit = _cache.get(path)
        if hit and hit[0] == stamp:
            return hit[1]
    with open(path, encoding="utf-8") as fh:
        text = fh.read(1_000_000 + 1)
    if len(text) > 1_000_000:
        raise EnrollmentError("enrollment file is larger than 1 MB")
    try:
        doc = json.loads(text, object_pairs_hook=_reject_duplicates)
    except json.JSONDecodeError as exc:
        raise EnrollmentError(f"not valid JSON: {exc.msg} at line {exc.lineno}") from None
    result = parse_enrollments(doc)
    with _cache_lock:
        _cache[path] = (stamp, result)
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
        key = (identity.email or identity.subject or "").strip().lower()
        found = table.get(key) if _EMAIL_RE.fullmatch(key) else None
    elif identity.kind == "service":
        found = table.get(_service_key(identity.subject))
    else:
        found = None
    if found is None:
        raise PermissionError("not enrolled")
    return found
