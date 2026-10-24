"""``proxmox-mcp-selfcheck``: prove the broker's secrets and least privilege, as JSON.

Run by the operator and by the Windows Test script (same environment as the
service). Offline checks always run; ``--live`` also asks Proxmox, over the same
pinned TLS the broker uses, what each enrolled token may actually do. That turns
least privilege from a setup step into a continuous control (SOC 2 CC6.2/CC6.3
evidence; HIPAA 164.308(a)(4), 164.308(a)(5)(ii)(D), 164.312(a)(2)(iv)).

Checks
  config            config.load(role) succeeds (typos, 0/1 booleans, bounds, https, hosts)
  dangerous_flags   each active dangerous flag is a WARN (evidence that it was on)
  credentials_dir   exists, is a directory, not a link; POSIX: no access for "other"
  stray_private_key no credential holds a PEM private key (the broker holds public keys only)
  enrollment        file exists, parses exactly as the broker parses it, not empty
  token:<subject>   readable, parseable, token user == proxmox_userid, not root@pam,
                    dedicated (not shared with another subject, not a @pam account)
  token_expiry      token_expires (YYYY-MM-DD) recorded; WARN <= 14 days; FAIL when reached
  worker_key        worker-identity.pub is an Ed25519 public key
  modes             no rw enrollment unless MCP_ALLOW_ADMIN_TOOLS=1 (rw also unlocks
                    DELETE in the outbound policy, so rw without admin is excess privilege)
  audit_path        the audit log (or its directory) is writable by the current user
  live:<subject>    GET /version and GET /access/permissions with the user's token; FAIL on
                    any privilege outside the allowed set for the user's mode, any always-
                    forbidden privilege, Datastore.Allocate on "/", or any privilege on "/"
                    that propagates.

Token expiry: Proxmox exposes a token's ``expire`` only under
/access/users/{user}/token/{name} (denied by the outbound policy: token management)
or in GET /access/users/{user} (needs Sys.Audit on /access, which would itself be
excess privilege). So the operator records the expiry chosen at
``pveum user token add --expire`` as ``token_expires`` in enrollment.json.

The /access/permissions call bypasses ProxmoxClient.request on purpose: that path is
not in the outbound allowlist (no tool needs it) and this is an operator tool. It
uses two fixed GET paths, the same TLS context and guard as the broker, no redirects,
no proxies, and a response cap.

Output: one JSON document on stdout. It contains subjects, Proxmox user ids, token
ids and privilege names, never a token secret. Exit codes: 0 all pass, 1 warnings
only, 2 at least one failure, 3 the selfcheck itself crashed, 64 usage error.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

import httpx

# Imported at module load on purpose: client.py loads .env at import, exactly as it
# does in the broker process, so the configuration checked here is the one it runs with.
from . import client as client_mod
from . import config, credentials, enrollment

EXIT_OK, EXIT_WARN, EXIT_FAIL, EXIT_CRASH, EXIT_USAGE = 0, 1, 2, 3, 64
EXPIRY_WARN_DAYS = 14
MAX_LIVE_RESPONSE = 4 * 1024 * 1024
_DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")

# ---- privilege model ------------------------------------------------------------------

ALWAYS_FORBIDDEN = frozenset(
    {
        "Sys.Modify",
        "Permissions.Modify",
        "User.Modify",
        "Group.Allocate",
        "Realm.Allocate",
        "Realm.AllocateUser",
        "Sys.Console",
        "VM.Console",
        "VM.GuestAgent.Unrestricted",
        "VM.GuestAgent.FileRead",
        "VM.GuestAgent.FileWrite",
        "VM.GuestAgent.FileSystemMgmt",
    }
)
_READ = frozenset(
    {
        "Datastore.Audit",
        "Mapping.Audit",
        "Pool.Audit",
        "SDN.Audit",
        "Sys.Audit",
        "Sys.Syslog",
        "VM.Audit",
        "VM.GuestAgent.Audit",
    }
)
_OPERATE = _READ | {"VM.PowerMgmt", "VM.Snapshot", "VM.Monitor"}
_ADMIN = _OPERATE | {
    "VM.Allocate",
    "VM.Backup",
    "VM.Clone",
    "VM.Migrate",
    "VM.Snapshot.Rollback",
    "VM.Config.CDROM",
    "VM.Config.CPU",
    "VM.Config.Cloudinit",
    "VM.Config.Disk",
    "VM.Config.HWType",
    "VM.Config.Memory",
    "VM.Config.Network",
    "VM.Config.Options",
    "Datastore.Allocate",
    "Datastore.AllocateSpace",
    "Datastore.AllocateTemplate",
    "Pool.Allocate",
    "SDN.Use",
    "Mapping.Use",
}
ALLOWED_PRIVILEGES: dict[str, frozenset[str]] = {
    "ro": frozenset(_READ),
    "operator": frozenset(_OPERATE),
    "rw": frozenset(_ADMIN),
}


def evaluate_permissions(perms: Any, mode: str) -> list[str]:
    """Violations in a GET /access/permissions ``data`` object ({path: {priv: propagate}})."""
    if not isinstance(perms, dict):
        return ["unexpected /access/permissions response"]
    allowed = ALLOWED_PRIVILEGES.get(mode, frozenset())
    out: list[str] = []
    for path in sorted(perms):
        privs = perms[path]
        if not isinstance(privs, dict):
            out.append(f"{path}: unexpected entry")
            continue
        for priv in sorted(privs):
            propagate = privs[priv] in (1, "1", True)
            if priv in ALWAYS_FORBIDDEN or priv.startswith("Realm."):
                out.append(f"{path}: {priv} is never allowed")
            elif priv == "Datastore.Allocate" and path == "/":
                out.append("/: Datastore.Allocate on / is never allowed")
            elif priv not in allowed:
                out.append(f"{path}: {priv} exceeds mode {mode}")
            if path == "/" and propagate:
                out.append(f"/: {priv} propagates from / (scope the ACL to a pool or path)")
    return out


# ---- report ------------------------------------------------------------------------------


@dataclass
class Check:
    id: str
    status: str  # pass | warn | fail | skip
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def _ok(cid: str, msg: str, **details: Any) -> Check:
    return Check(cid, "pass", msg, details)


def _warn(cid: str, msg: str, **details: Any) -> Check:
    return Check(cid, "warn", msg, details)


def _fail(cid: str, msg: str, **details: Any) -> Check:
    return Check(cid, "fail", msg, details)


def overall(checks: Iterable[Check]) -> tuple[str, int]:
    statuses = {c.status for c in checks}
    if "fail" in statuses:
        return "fail", EXIT_FAIL
    if "warn" in statuses:
        return "warn", EXIT_WARN
    return "pass", EXIT_OK


# ---- offline checks ----------------------------------------------------------------------


def check_config(
    environ: Mapping[str, str] | None, role: str
) -> tuple[config.Settings | None, list[Check]]:
    try:
        settings = config.load(environ, role=role)
    except config.ConfigError as exc:
        return None, [_fail("config", "configuration is invalid", problems=exc.problems)]
    checks = [
        _ok(
            "config",
            "configuration is valid",
            config_sha256=settings.config_sha256(),
            tls_mode=settings.tls_mode,
        )
    ]
    for flag in settings.dangerous_flags():
        checks.append(_warn("dangerous_flags", f"{flag} is active", flag=flag))
    return settings, checks


def check_credentials_dir(settings: config.Settings) -> list[Check]:
    path = settings.credentials_dir
    if not path:
        return [_fail("credentials_dir", "no credential directory configured")]
    try:
        st = os.lstat(path)
    except OSError:
        return [_fail("credentials_dir", "credential directory does not exist or is not readable")]
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return [_fail("credentials_dir", "credential path is not a plain directory")]
    if credentials.IS_WINDOWS:
        return [_ok("credentials_dir", "exists (ACL is set by the installer; not re-checked here)")]
    if st.st_mode & stat.S_IWOTH or st.st_mode & stat.S_IWGRP:
        return [_fail("credentials_dir", "credential directory is writable by group or others")]
    if st.st_mode & stat.S_IRWXO:
        return [
            _warn("credentials_dir", "credential directory is accessible to others (expect 0700)")
        ]
    return [_ok("credentials_dir", "exists, not accessible to others")]


def check_stray_private_keys(settings: config.Settings) -> list[Check]:
    found = []
    try:
        names = sorted(os.listdir(settings.credentials_dir or ""))
    except OSError:
        return []
    for entry in names:
        name = (
            entry[: -len(credentials.DPAPI_SUFFIX)]
            if entry.endswith(credentials.DPAPI_SUFFIX)
            else entry
        )
        if not credentials.NAME_RE.match(name):
            continue
        try:
            text = credentials.read_credential(name)
        except (credentials.CredentialError, OSError):
            continue
        if "PRIVATE KEY-----" in text:
            found.append(name)
        del text
    if found:
        return [
            _fail(
                "stray_private_key",
                "private key material in the credential directory; remove it and rotate the key",
                credentials=found,
            )
        ]
    return [_ok("stray_private_key", "no private keys in the credential directory")]


def _subject_key(section: str, raw: str) -> str:
    return raw.strip().lower() if section == "users" else f"service:{raw}"


def check_enrollment(
    settings: config.Settings,
) -> tuple[dict[str, enrollment.Enrollment], dict[str, Any], list[Check]]:
    path = settings.enrollment_file
    if not path or not os.path.isfile(path):
        return (
            {},
            {},
            [_fail("enrollment", "enrollment file is missing (nobody can use the broker)")],
        )
    try:
        table = enrollment.load_enrollments(path)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        return {}, {}, [_fail("enrollment", f"enrollment file is invalid: {exc}")]
    raw: dict[str, Any] = {}
    for section in ("users", "services"):
        for subject, entry in (doc.get(section) or {}).items():
            raw[_subject_key(section, subject)] = entry
    if not table:
        return table, raw, [_warn("enrollment", "enrollment file grants nobody")]
    return (
        table,
        raw,
        [
            _ok(
                "enrollment",
                f"{len(table)} subject(s) enrolled",
                modes={k: e.mode for k, e in sorted(table.items())},
            )
        ],
    )


def check_tokens(table: Mapping[str, enrollment.Enrollment]) -> list[Check]:
    checks: list[Check] = []
    by_userid: dict[str, list[str]] = {}
    by_cred: dict[str, list[str]] = {}
    by_digest: dict[str, list[str]] = {}
    for key, ent in sorted(table.items()):
        by_userid.setdefault(ent.proxmox_userid.lower(), []).append(key)
        by_cred.setdefault(ent.token_credential, []).append(key)
        cid = f"token:{key}"
        try:
            text = credentials.read_credential(ent.token_credential)
        except credentials.CredentialError as exc:
            checks.append(_fail(cid, f"token credential unusable: {exc}"))
            continue
        try:
            token = credentials.parse_api_token(text, expected_userid=ent.proxmox_userid)
        except credentials.CredentialError as exc:
            checks.append(_fail(cid, str(exc)))
            continue
        finally:
            del text
        digest = hashlib.sha256(token.secret.encode("utf-8")).hexdigest()
        by_digest.setdefault(digest, []).append(key)
        token_id = token.token_id
        del token, digest
        realm = ent.proxmox_userid.rsplit("@", 1)[-1].lower()
        if ent.proxmox_userid.lower() == "root@pam":
            checks.append(_fail(cid, "token belongs to root@pam", token_id=token_id))
        elif realm == "pam":
            checks.append(
                _warn(
                    cid,
                    "token user is a @pam (Linux) account; use a dedicated @pve user",
                    token_id=token_id,
                )
            )
        else:
            checks.append(_ok(cid, "token readable and matches proxmox_userid", token_id=token_id))
    for label, groups in (
        ("Proxmox user", by_userid),
        ("token credential", by_cred),
        ("token secret", by_digest),
    ):
        for subjects in groups.values():
            if len(subjects) > 1:
                checks.append(
                    _fail(
                        "dedicated_user",
                        f"{label} shared by several subjects (one person, one key)",
                        subjects=subjects,
                    )
                )
    return checks


def parse_token_expires(value: Any) -> dt.date:
    if not isinstance(value, str) or not _DATE_RE.match(value):
        raise ValueError("token_expires must be an ISO date YYYY-MM-DD")
    return dt.date.fromisoformat(value)


def check_token_expiry(
    table: Mapping[str, enrollment.Enrollment],
    raw: Mapping[str, Any],
    today: dt.date,
    warn_days: int = EXPIRY_WARN_DAYS,
) -> list[Check]:
    checks: list[Check] = []
    for key in sorted(table):
        ent = table[key]
        cid = f"token_expiry:{key}"
        value = getattr(ent, "token_expires", None)
        if value is None and isinstance(raw.get(key), dict):
            value = raw[key].get("token_expires")
        if value is None:
            checks.append(
                _warn(
                    cid,
                    "no token_expires recorded; create tokens with --expire "
                    "and record the date in enrollment.json",
                )
            )
            continue
        try:
            expires = value if isinstance(value, dt.date) else parse_token_expires(value)
        except ValueError as exc:
            checks.append(_fail(cid, str(exc)))
            continue
        left = (expires - today).days
        if left <= 0:
            checks.append(_fail(cid, "token has expired; rotate it", expires=expires.isoformat()))
        elif left <= warn_days:
            checks.append(
                _warn(
                    cid, f"token expires in {left} day(s); rotate it", expires=expires.isoformat()
                )
            )
        else:
            checks.append(
                _ok(cid, f"token valid for {left} more day(s)", expires=expires.isoformat())
            )
    return checks


def check_worker_key(settings: config.Settings) -> list[Check]:
    if settings.role == "stdio":
        return []
    from .transport import identity_assertion as ia

    try:
        pem = credentials.read_credential(ia.PUBLIC_KEY_CREDENTIAL)
    except credentials.CredentialError as exc:
        return [_fail("worker_key", f"cannot read {ia.PUBLIC_KEY_CREDENTIAL}: {exc}")]
    if "PRIVATE KEY" in pem:
        return [
            _fail(
                "worker_key",
                f"{ia.PUBLIC_KEY_CREDENTIAL} holds a PRIVATE key; remove it "
                "from the broker and rotate the Worker key",
            )
        ]
    try:
        ia.load_public_key(pem)
    except ia.AssertionConfigError as exc:
        return [_fail("worker_key", str(exc))]
    return [_ok("worker_key", "Ed25519 public key")]


def check_modes(
    settings: config.Settings, table: Mapping[str, enrollment.Enrollment]
) -> list[Check]:
    rw = sorted(k for k, e in table.items() if e.mode == "rw")
    if not rw:
        return [_ok("modes", "no rw enrollments")]
    if not settings.allow_admin_tools:
        return [
            _fail(
                "modes",
                "rw enrollments without MCP_ALLOW_ADMIN_TOOLS=1 grant DELETE at the "
                "outbound policy with no admin tool to use it; enroll them as operator",
                subjects=rw,
            )
        ]
    return [
        _warn("modes", "rw enrollments with admin tools enabled; review quarterly", subjects=rw)
    ]


def check_audit_path(settings: config.Settings) -> list[Check]:
    from . import audit

    path = settings.audit_log or audit.default_path()
    who = getpass.getuser()
    try:
        if os.path.exists(path):
            flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0)
            os.close(os.open(path, flags))  # opens for append, writes nothing
        else:
            fd, probe = tempfile.mkstemp(prefix=".selfcheck-", dir=os.path.dirname(path) or ".")
            os.close(fd)
            os.unlink(probe)
    except OSError as exc:
        return [
            _fail(
                "audit_path",
                f"audit log is not writable ({type(exc).__name__})",
                path=path,
                checked_as=who,
            )
        ]
    return [_ok("audit_path", "audit log is writable", path=path, checked_as=who)]


# ---- live checks ---------------------------------------------------------------------------


async def _get(http: httpx.AsyncClient, url: str, header: str) -> Any:
    req = http.build_request(
        "GET", url, headers={"Authorization": header, "Accept": "application/json"}
    )
    try:
        response = await http.send(req, stream=True, follow_redirects=False)
        try:
            body = b""
            async for chunk in response.aiter_bytes():
                body += chunk
                if len(body) > MAX_LIVE_RESPONSE:
                    raise ValueError("response too large")
        finally:
            await response.aclose()
    finally:
        req.headers.pop("Authorization", None)  # do not keep the token alive on the request
    if response.status_code == 401:
        raise PermissionError("token rejected by Proxmox (revoked, expired or wrong secret)")
    if response.status_code != 200:
        raise PermissionError(f"HTTP {response.status_code}")
    doc = json.loads(body)
    if not isinstance(doc, dict):
        raise ValueError("unexpected response")
    return doc.get("data")


async def live_checks(
    settings: config.Settings,
    table: Mapping[str, enrollment.Enrollment],
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[Check]:
    base = client_mod.base_url(settings.proxmox_host, str(settings.proxmox_port))
    if transport is None:
        pins = tuple(bytes.fromhex(p) for p in settings.proxmox_tls_fingerprints)
        ctx = client_mod.build_ssl_context(
            settings.proxmox_ca_bundle or "", pins, settings.proxmox_insecure_tls
        )
        transport = client_mod.GuardedTransport(ctx, pins)
    checks: list[Check] = []
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(settings.proxmox_timeout),
        follow_redirects=False,
        trust_env=False,
    ) as http:
        for key, ent in sorted(table.items()):
            cid = f"live:{key}"
            try:
                header = credentials.parse_api_token(
                    credentials.read_credential(ent.token_credential),
                    expected_userid=ent.proxmox_userid,
                ).header()
            except credentials.CredentialError as exc:
                checks.append(Check(cid, "skip", f"token unusable: {exc}"))
                continue
            try:
                version = await _get(http, f"{base}/version", header)
                perms = await _get(http, f"{base}/access/permissions", header)
            except (PermissionError, ValueError, httpx.HTTPError) as exc:
                checks.append(_fail(cid, f"live check failed: {type(exc).__name__}: {exc}"))
                continue
            finally:
                del header
            problems = evaluate_permissions(perms, ent.mode)
            ver = version.get("version") if isinstance(version, dict) else None
            if problems:
                checks.append(
                    _fail(
                        cid,
                        "token holds privileges outside its mode",
                        mode=ent.mode,
                        violations=problems,
                        proxmox_version=ver,
                    )
                )
            else:
                checks.append(
                    _ok(
                        cid,
                        "token privileges within mode",
                        mode=ent.mode,
                        paths=len(perms) if isinstance(perms, dict) else 0,
                        proxmox_version=ver,
                    )
                )
    return checks


# ---- driver ----------------------------------------------------------------------------------


def run_checks(
    *,
    role: str = "broker",
    live: bool = False,
    environ: Mapping[str, str] | None = None,
    today: dt.date | None = None,
    warn_days: int = EXPIRY_WARN_DAYS,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    today = today or dt.datetime.now(dt.timezone.utc).date()
    settings, checks = check_config(environ, role)
    if settings is not None:
        checks += check_credentials_dir(settings)
        checks += check_stray_private_keys(settings)
        table, raw, enr = check_enrollment(settings)
        checks += enr
        checks += check_tokens(table)
        checks += check_token_expiry(table, raw, today, warn_days)
        checks += check_worker_key(settings)
        checks += check_modes(settings, table)
        checks += check_audit_path(settings)
        if live and table:
            checks += asyncio.run(live_checks(settings, table, transport))
    status, code = overall(checks)
    return {
        "tool": "proxmox-mcp-selfcheck",
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "role": role,
        "live": live,
        "status": status,
        "exit_code": code,
        "counts": {s: sum(c.status == s for c in checks) for s in ("pass", "warn", "fail", "skip")},
        "checks": [asdict(c) for c in checks],
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="proxmox-mcp-selfcheck", description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true", help="also query Proxmox with each token")
    parser.add_argument("--role", choices=("broker", "stdio"), default="broker")
    parser.add_argument("--warn-days", type=int, default=EXPIRY_WARN_DAYS)
    args = parser.parse_args(argv)
    try:
        report = run_checks(role=args.role, live=args.live, warn_days=args.warn_days)
    except Exception as exc:  # the report must still be JSON; type only, no detail
        print(
            json.dumps(
                {"tool": "proxmox-mcp-selfcheck", "status": "crash", "error": type(exc).__name__}
            )
        )
        return EXIT_CRASH
    print(json.dumps(report, indent=2, sort_keys=False))
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
