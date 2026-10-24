"""Secrets for the broker: systemd credentials (Linux) or a DPAPI/ACL'd directory (Windows).

Credential directory, first match wins (fail closed when none is set):
  1. BROKER_CREDENTIALS_DIR  (Windows broker: C:\\ProgramData\\ProxmoxMCP\\credentials)
  2. CREDENTIALS_DIRECTORY   (systemd LoadCredential= / LoadCredentialEncrypted=, Linux)

Secrets never pass through the environment (visible to anything that can read the
process environment and inherited by children) and are never logged; errors name
the credential, never its content.

Reading ``<name>``:
- the name must match a strict pattern, so it cannot name a path;
- if ``<name>.dpapi`` exists it is decrypted with DPAPI CryptUnprotectData (ctypes,
  no pywin32). Blobs are made by ``proxmox-mcp-protect-credential`` with
  CRYPTPROTECT_LOCAL_MACHINE plus optional entropy read from
  BROKER_DPAPI_ENTROPY_FILE. LocalMachine scope means any process on the host
  could call DPAPI, so the file ACL (service SID only) and the entropy file (also
  ACL'd to the service SID) are what keep other local accounts out; DPAPI keeps
  the secret unreadable in backups/copies of the directory taken off the host.
- else ``<name>`` is read as plaintext.
- symlinks / reparse points are refused. On POSIX the file must be a regular file
  owned by the service user or root with no "other" bits and no group write bit
  (systemd creates them 0400/0440). On Windows mode bits are meaningless; the
  installer sets an ACL granting read to NT SERVICE\\ProxmoxMCPBroker and
  Administrators only, which this module does not re-check (that would need the
  Win32 security API; documented in docs/SECURITY.md).
- at most 64 KiB, valid UTF-8; one trailing newline is stripped.

A Proxmox API token credential holds exactly one line ``user@realm!tokenname=<uuid>``.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass, field

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_BYTES = 64 * 1024
DPAPI_SUFFIX = ".dpapi"
IS_WINDOWS = sys.platform == "win32"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# Proxmox userid "name@realm", token name, and a UUID secret (what pveum generates).
TOKEN_RE = re.compile(
    r"^(?P<userid>[A-Za-z0-9._+-]{1,64}@[A-Za-z][A-Za-z0-9._-]{0,31})"
    r"!(?P<tokenname>[A-Za-z][A-Za-z0-9._-]{0,63})"
    r"=(?P<secret>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


class CredentialError(PermissionError):
    """A credential is missing, unsafe, or malformed. Message never contains the value."""


def credentials_dir() -> str:
    for var in ("BROKER_CREDENTIALS_DIR", "CREDENTIALS_DIRECTORY"):
        directory = os.environ.get(var, "")
        if directory:
            if not os.path.isabs(directory):
                raise CredentialError(f"{var} must be an absolute path")
            return directory
    raise CredentialError("no credential directory (BROKER_CREDENTIALS_DIR / CREDENTIALS_DIRECTORY)")


def _check_name(name: object) -> str:
    if (
        not isinstance(name, str)
        or not NAME_RE.fullmatch(name)
        or ".." in name
        or name.lower().endswith(DPAPI_SUFFIX)
    ):
        raise CredentialError("invalid credential name")
    return name


def credential_path(name: str) -> str:
    """Path of the file that holds ``name``: the .dpapi blob when present, else plaintext."""
    base = os.path.join(credentials_dir(), _check_name(name))
    if os.path.lexists(base + DPAPI_SUFFIX):
        return base + DPAPI_SUFFIX
    return base


def _check_stat(name: str, st: os.stat_result) -> None:
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise CredentialError(f"credential {name!r} is a link")
    if not stat.S_ISREG(st.st_mode):
        raise CredentialError(f"credential {name!r} is not a regular file")
    if st.st_size > MAX_BYTES:
        raise CredentialError(f"credential {name!r} is too large")
    if IS_WINDOWS:
        return  # ACLs, not mode bits; set by the installer (see module docstring)
    if st.st_mode & (stat.S_IRWXO | stat.S_IWGRP):
        raise CredentialError(f"credential {name!r} is accessible to other users (expect 0400)")
    if st.st_uid not in (os.geteuid(), 0):
        raise CredentialError(f"credential {name!r} is owned by another user")
    if st.st_nlink != 1:
        # A second name for the file (hard link) lives outside this directory's control.
        raise CredentialError(f"credential {name!r} has more than one link")


def stat_credential(name: str) -> os.stat_result:
    """lstat of the credential file (used for cache invalidation); same checks as a read."""
    path = credential_path(name)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise CredentialError(f"credential {name!r} not found") from None
    except OSError:
        raise CredentialError(f"credential {name!r} is not readable") from None
    _check_stat(name, st)
    return st


def _read_file(name: str, path: str) -> tuple[bytes, os.stat_result]:
    """Contents and the fstat of the descriptor they were read from."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before = os.lstat(path)
        _check_stat(name, before)  # catches links on Windows, where O_NOFOLLOW is absent
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise CredentialError(f"credential {name!r} not found") from None
    except CredentialError:
        raise
    except OSError:
        # ELOOP for a symlink, EACCES, ...
        raise CredentialError(f"credential {name!r} is not readable") from None
    try:
        st = os.fstat(fd)
        _check_stat(name, st)
        if not st.st_ino or (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            # Also the Windows reparse-point race: lstat saw a file, open followed a link.
            raise CredentialError(f"credential {name!r} changed while opening")
        raw = b""
        while len(raw) <= MAX_BYTES:
            chunk = os.read(fd, MAX_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    if len(raw) > MAX_BYTES:
        raise CredentialError(f"credential {name!r} is too large")
    return raw, st


def _dpapi_entropy() -> bytes | None:
    path = os.environ.get("BROKER_DPAPI_ENTROPY_FILE", "")
    if not path:
        return None
    if not os.path.isabs(path):
        raise CredentialError("BROKER_DPAPI_ENTROPY_FILE must be an absolute path")
    return _read_file("dpapi-entropy", path)[0]


def read_credential(name: str) -> str:
    """The credential's text, one trailing newline stripped. Raises CredentialError."""
    return read_credential_with_stat(name)[0]


def read_credential_with_stat(name: str) -> tuple[str, os.stat_result]:
    """Like read_credential, plus the fstat of the file actually read (for caching)."""
    path = credential_path(name)
    raw, st = _read_file(name, path)
    if path.endswith(DPAPI_SUFFIX):
        try:
            raw = dpapi_unprotect(raw, _dpapi_entropy())
        except CredentialError:
            raise
        except Exception:
            raise CredentialError(f"credential {name!r} could not be decrypted") from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CredentialError(f"credential {name!r} is not valid UTF-8") from None
    # Windows PowerShell 5.1 "Set-Content -Encoding UTF8" writes a BOM.
    if text.startswith("\ufeff"):
        text = text[1:]
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text:
        raise CredentialError(f"credential {name!r} is empty")
    return text, st


# --- DPAPI (Windows, ctypes) ------------------------------------------------------------

CRYPTPROTECT_UI_FORBIDDEN = 0x1
CRYPTPROTECT_LOCAL_MACHINE = 0x4


def _dpapi_call(fn_name: str, data: bytes, entropy: bytes | None, flags: int) -> bytes:
    if not IS_WINDOWS:
        raise CredentialError("DPAPI credentials are only supported on Windows")
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):  # noqa: N801 (Win32 name)
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    def blob(b: bytes) -> tuple[DATA_BLOB, object]:
        buf = ctypes.create_string_buffer(b, len(b))
        return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = getattr(crypt32, fn_name)
    in_blob, _keep_in = blob(data)
    out_blob = DATA_BLOB()
    if entropy is not None:
        ent_blob, _keep_ent = blob(entropy)
        ent_ptr = ctypes.byref(ent_blob)
    else:
        ent_ptr = None
    # Both functions: (pDataIn, szDescr, pEntropy, pvReserved, pPrompt, dwFlags, pDataOut).
    ok = fn(ctypes.byref(in_blob), None, ent_ptr, None, None, flags, ctypes.byref(out_blob))
    if not ok:
        raise CredentialError(f"{fn_name} failed (error {ctypes.get_last_error()})")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out_blob.pbData, ctypes.c_void_p))


def dpapi_unprotect(blob: bytes, entropy: bytes | None = None) -> bytes:
    return _dpapi_call("CryptUnprotectData", blob, entropy, CRYPTPROTECT_UI_FORBIDDEN)


def dpapi_protect(data: bytes, entropy: bytes | None = None) -> bytes:
    flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE
    return _dpapi_call("CryptProtectData", data, entropy, flags)


def protect_main(argv: list[str] | None = None) -> int:
    """``proxmox-mcp-protect-credential <name> [--force]``: DPAPI-encrypt stdin to <dir>/<name>.dpapi.

    The secret is read from stdin only (never argv, which other users can see in
    the process list). Run it elevated, as the installer does; set
    BROKER_CREDENTIALS_DIR and optionally BROKER_DPAPI_ENTROPY_FILE first.
    """
    import argparse
    import getpass

    parser = argparse.ArgumentParser(prog="proxmox-mcp-protect-credential")
    parser.add_argument("name", help="credential name, e.g. pve-token-alice")
    parser.add_argument("--force", action="store_true", help="replace an existing .dpapi file")
    args = parser.parse_args(argv)
    if not IS_WINDOWS:
        print("error: DPAPI is only available on Windows", file=sys.stderr)
        return 2
    try:
        name = _check_name(args.name)
        target = os.path.join(credentials_dir(), name + DPAPI_SUFFIX)
        if sys.stdin.isatty():
            secret = getpass.getpass("secret: ")
        else:
            secret = sys.stdin.read(MAX_BYTES + 1)
        secret = secret.rstrip("\r\n")
        if not secret or len(secret.encode("utf-8")) > MAX_BYTES:
            print("error: secret is empty or too large", file=sys.stderr)
            return 2
        blob = dpapi_protect(secret.encode("utf-8"), _dpapi_entropy())
        del secret
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= os.O_TRUNC if args.force else os.O_EXCL
        fd = os.open(target, flags, 0o600)
        try:
            os.write(fd, blob)
        finally:
            os.close(fd)
    except (CredentialError, FileExistsError, OSError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {name}{DPAPI_SUFFIX}", file=sys.stderr)
    return 0


@dataclass(frozen=True)
class ApiToken:
    """A parsed Proxmox API token. repr() never shows the secret."""

    userid: str
    tokenname: str
    secret: str = field(repr=False)

    @property
    def token_id(self) -> str:
        """``user@realm!tokenname``: not secret, safe for audit lines."""
        return f"{self.userid}!{self.tokenname}"

    def header(self) -> str:
        return f"PVEAPIToken={self.userid}!{self.tokenname}={self.secret}"


def parse_api_token(text: str, *, expected_userid: str | None = None) -> ApiToken:
    """Parse ``user@realm!tokenname=uuid``; optionally require the user part to match."""
    m = TOKEN_RE.fullmatch(text.strip()) if isinstance(text, str) else None
    if not m:
        raise CredentialError("API token credential is malformed (expect user@realm!name=<uuid>)")
    token = ApiToken(m["userid"], m["tokenname"], m["secret"])
    if expected_userid is not None and token.userid != expected_userid:
        raise CredentialError("API token belongs to a different Proxmox user than the enrollment")
    return token
