"""Central, typed, fail-closed settings for the broker, the stdio server and selfcheck.

One frozen ``Settings`` is parsed from the environment once, at startup, and is
the single source of truth for every tunable (HIPAA 164.312(a)(2)(iv) and
164.308(a)(5)(ii)(D) configuration hygiene; SOC 2 CC6.1/CC6.6 secure
configuration, CC8.1 change evidence via ``config_sha256``).

Parsing rules (all violations are collected and raised together as ConfigError;
messages name variables, never values, because a value may be a secret):

- Typo protection: every variable whose name starts with PROXMOX_, MCP_, BROKER_
  or CF_ACCESS_ must be one this module knows. An unknown one (``MCP_ALOW_ADMIN_TOOLS``)
  stops startup with a "did you mean" hint instead of being silently ignored.
  Removed settings (PROXMOX_PASSWORD, PROXMOX_VERIFY_SSL, ...) get a specific message.
  The few variables MCP clients inject into servers they spawn (FOREIGN_VARS, e.g.
  Claude Code's MCP_TOOL_TIMEOUT) are ignored by name.
- Booleans are exactly "0" or "1". "true", "yes", "1 " and "1\\r" (a CRLF env file
  on Windows) are errors, not guesses.
- An empty value means "unset" (compose files and service wrappers produce empty
  strings); the default applies, and every default is the safe one.
- No value may contain control characters or leading/trailing whitespace.
- Integers are bounded; paths must be absolute; URLs must be https origins; host
  names and IP literals are validated; regexes must compile.
- Role checks: ``broker`` (Windows/Linux service behind the Worker), ``stdio``
  (developer workstation) and ``selfcheck`` (same as broker). The broker refuses
  Proxmox token material in the environment (tokens come from the credential
  store only), refuses a non-loopback bind without MCP_ALLOW_NON_LOOPBACK=1, and
  refuses PROXMOX_INSECURE_TLS=1 unless a certificate fingerprint pin is set
  (164.312(e)(1): a bearer token is never written to an unverified peer).
- Dangerous flags (PROXMOX_INSECURE_TLS, MCP_ALLOW_NON_LOOPBACK,
  MCP_ALLOW_SERVICE_TOKENS, MCP_ALLOW_ADMIN_TOOLS, BROKER_REQUIRE_ACCESS_JWT=0) are
  logged at WARNING on every start (``init``) and listed in the audit start
  event (``audit_start_fields``).

This module does not load ``.env`` files. The broker must not: a service's working
directory is not a configuration source anyone reviews. The stdio entry point may
call ``dotenv.load_dotenv()`` before ``init("stdio")``.

Memory hygiene (what Python can and cannot do)
-----------------------------------------------
Cannot: ``str`` and ``bytes`` are immutable, may be interned or copied by every
decode, f-string, header encoding (httpx turns the Authorization value into
bytes) and TLS write buffer, and freed memory is not zeroed. There is no
portable ``mlock``; the interpreter may be paged to the pagefile/swap or captured
in a crash dump. A ``bytearray`` can be zeroed, but the copies made to use it
cannot. So "secure zeroing" of a token in CPython is not achievable and this
code does not pretend otherwise.

Can, and does:
- keep secrets out of the environment on the broker (process environment is
  readable by same-user processes and inherited by children);
- keep the lifetime short: read from the credential store per request (cached
  parsed token, re-read on file change), build the header, ``del`` the locals;
- never log, audit, repr or str a secret: ``SecretStr`` here and
  ``credentials.ApiToken`` redact ``repr``; error messages name the credential,
  never its content; the audit layer drops secret-looking keys;
- refuse pickling of secret holders (``SecretStr``), so a secret cannot leak via
  a cache, multiprocessing queue or debug dump by serialisation;
- compare secrets in constant time.
Operational controls that cover the rest (documented for DEPLOY): BitLocker on the
broker volume (covers the pagefile at rest), disable Windows Error Reporting full
dumps for the service account, never enable tracebacks-with-locals (rich,
Sentry ``include_local_variables``, uvicorn debug) on the broker, and keep
token lifetimes short (``token_expires`` in enrollment.json, enforced by
``proxmox-mcp-selfcheck``).
"""

from __future__ import annotations

import difflib
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field, fields
from typing import Any, Literal
from urllib.parse import urlsplit

log = logging.getLogger("proxmox_mcp.config")

Role = Literal["broker", "stdio", "selfcheck"]
ROLES: tuple[str, ...] = ("broker", "stdio", "selfcheck")
MODES: tuple[str, ...] = ("ro", "operator", "rw")
TOOL_MODES: tuple[str, ...] = ("dynamic", "static")

CHECKED_PREFIXES: tuple[str, ...] = ("PROXMOX_", "MCP_", "BROKER_", "CF_ACCESS_")

# Every variable the code base reads. Unknown names under CHECKED_PREFIXES are errors.
KNOWN_VARS: dict[str, str] = {
    # Proxmox API endpoint and TLS
    "PROXMOX_HOST": "Proxmox host name or IP literal (no scheme, port or path)",
    "PROXMOX_PORT": "Proxmox API port, 1-65535 (default 8006)",
    "PROXMOX_CA_BUNDLE": "absolute path of a PEM CA bundle for the Proxmox API",
    "PROXMOX_TLS_FINGERPRINT": "SHA-256 leaf certificate pin(s), comma-separated",
    "PROXMOX_INSECURE_TLS": "1 disables TLS verification (DANGEROUS; broker needs a pin)",
    "PROXMOX_READ_ONLY": "1 refuses every non-GET request (kill switch)",
    "PROXMOX_TIMEOUT": "Proxmox request timeout in seconds, 1-600 (default 30)",
    "PROXMOX_MAX_RESPONSE_BYTES": "Proxmox response cap, 64 KiB-1 GiB (default 64 MiB)",
    # stdio developer identity (forbidden on the broker)
    "PROXMOX_USER": "stdio only: Proxmox user@realm of the developer token",
    "PROXMOX_TOKEN_NAME": "stdio only: token name of the developer token",
    "PROXMOX_TOKEN_VALUE": "stdio only: token secret (never on the broker)",
    "MCP_LOCAL_MODE": "stdio only: ro | operator | rw (default ro)",
    # tool policy
    "MCP_TOOL_MODE": "dynamic | static (default dynamic)",
    "MCP_ALLOW_ADMIN_TOOLS": "1 enables admin-tier tools for rw users (DANGEROUS)",
    "MCP_TOOL_ALLOW": "comma-separated tool names; when set only these may run",
    "MCP_TOOL_DENY": "comma-separated regexes of tool names that may never run",
    "MCP_RATE_PER_MIN": "per-user calls per minute, 1-10000 (default 60)",
    "MCP_RATE_PER_DAY": "per-user calls per day, 1-1000000 (default 2000)",
    # output
    "MCP_MAX_RESULT_BYTES": "rendered tool result cap, 1 KiB-64 MiB (default 2 MiB)",
    "MCP_PHI_CONTACT": "1 also redacts e-mail addresses and phone numbers",
    # audit and secrets
    "MCP_AUDIT_LOG": "absolute path of the hash-chained audit log",
    "MCP_ENROLLMENT_FILE": "absolute path of enrollment.json",
    "BROKER_CREDENTIALS_DIR": "absolute path of the broker credential directory (Windows)",
    "BROKER_DPAPI_ENTROPY_FILE": "absolute path of the DPAPI entropy file (Windows)",
    # broker HTTP guard
    "MCP_BIND": "listen address, an IP literal or localhost (default 127.0.0.1)",
    "MCP_PORT": "listen port, 1-65535 (default 8765)",
    "MCP_ALLOW_NON_LOOPBACK": "1 permits a non-loopback bind (DANGEROUS)",
    "MCP_ALLOWED_HOSTS": "comma-separated Host header allowlist (default loopback names)",
    "MCP_MAX_REQUEST_BYTES": "request body cap, 1 KiB-4 MiB (default 256 KiB)",
    "MCP_REQUEST_TIMEOUT": "per-request timeout in seconds, 5-900 (default 120)",
    "MCP_MAX_CONCURRENCY": "concurrent requests, 1-4096 (default 64)",
    "BROKER_REQUIRE_ACCESS_JWT": "0 disables the Access service-token check (Workers VPC mode)",
    "BROKER_ALLOWED_SERVICE_CLIENT_IDS": "comma-separated Access service token client ids",
    "CF_ACCESS_TEAM_DOMAIN": "https://<team>.cloudflareaccess.com",
    "CF_ACCESS_AUD": "comma-separated Access application AUD tags",
    "MCP_ALLOW_SERVICE_TOKENS": "1 accepts Access service tokens as callers (DANGEROUS)",
}

# Read by the code but outside CHECKED_PREFIXES (validated, not typo-checked).
OTHER_VARS: dict[str, str] = {
    "CREDENTIALS_DIRECTORY": "set by systemd LoadCredential= (Linux)",
}

REMOVED_VARS: dict[str, str] = {
    "PROXMOX_PASSWORD": "password/ticket auth was removed; use a per-user API token",
    "PROXMOX_VERIFY_SSL": (
        "removed; TLS is always verified. Use PROXMOX_CA_BUNDLE or PROXMOX_TLS_FINGERPRINT"
    ),
    "MCP_SERVER_TYPE": "unused upstream leftover; remove it",
}

# Set by MCP *clients* (Claude Code, Claude Desktop) in the environment of the servers
# they spawn, so a stdio server inherits them. Not ours, never read; ignored rather than
# treated as typos. Kept explicit and short so a real typo still fails.
FOREIGN_VARS: frozenset[str] = frozenset(
    {"MCP_TIMEOUT", "MCP_TOOL_TIMEOUT", "MCP_CONNECTION_NONBLOCKING"}
)

DANGEROUS_FLAGS: tuple[str, ...] = (
    "PROXMOX_INSECURE_TLS",
    "MCP_ALLOW_NON_LOOPBACK",
    "MCP_ALLOW_SERVICE_TOKENS",
    "MCP_ALLOW_ADMIN_TOOLS",
    "BROKER_REQUIRE_ACCESS_JWT=0",
)

DEFAULT_PROXMOX_PORT = 8006
DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8765
_LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
_HOST_ENTRY_RE = re.compile(r"^[a-z0-9.-]+(:[0-9]{1,5})?$|^\[[0-9a-f:.]+\](:[0-9]{1,5})?$")
_TOOL_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_AUD_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_USERID_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}@[A-Za-z][A-Za-z0-9._-]{0,31}$")
_TOKEN_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class ConfigError(RuntimeError):
    """The configuration is unusable. ``problems`` lists each one (names, never values)."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = list(problems)
        super().__init__("invalid configuration: " + "; ".join(self.problems))


class SecretStr:
    """A secret string that never shows itself.

    ``repr``/``str``/``format`` give ``<redacted>``; pickling and copying by
    serialisation raise; equality is constant time. ``reveal()`` returns the
    value for the one place that must send it; delete that local right after.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("SecretStr wraps a str")
        object.__setattr__(self, "_value", value)

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SecretStr('<redacted>')"

    def __str__(self) -> str:
        return "<redacted>"

    def __format__(self, spec: str) -> str:
        return "<redacted>"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretStr):
            return NotImplemented
        return hmac.compare_digest(self._value.encode("utf-8"), other._value.encode("utf-8"))

    def __hash__(self) -> int:
        # Hash of a digest, not of the value: a hash() leak must not be a guessing oracle.
        return hash(hashlib.sha256(self._value.encode("utf-8")).digest())

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("SecretStr is immutable")

    def __reduce__(self) -> Any:
        raise TypeError("SecretStr cannot be pickled or copied by serialisation")

    def __reduce_ex__(self, protocol: Any) -> Any:
        raise TypeError("SecretStr cannot be pickled or copied by serialisation")


@dataclass(frozen=True)
class Settings:
    role: str
    # Proxmox endpoint + TLS
    proxmox_host: str
    proxmox_port: int = DEFAULT_PROXMOX_PORT
    proxmox_ca_bundle: str | None = None
    proxmox_tls_fingerprints: tuple[str, ...] = ()  # lowercase hex, no colons
    proxmox_insecure_tls: bool = False
    proxmox_read_only: bool = False
    proxmox_timeout: int = 30
    proxmox_max_response_bytes: int = 64 * 1024 * 1024
    # stdio developer identity
    proxmox_user: str | None = None
    proxmox_token_name: str | None = None
    proxmox_token_value: SecretStr | None = field(default=None, repr=False, compare=False)
    local_mode: str = "ro"
    # policy
    tool_mode: str = "dynamic"
    allow_admin_tools: bool = False
    tool_allow: tuple[str, ...] = ()
    tool_deny: tuple[str, ...] = ()
    rate_per_min: int = 60
    rate_per_day: int = 2000
    # output
    max_result_bytes: int = 2 * 1024 * 1024
    phi_contact: bool = False
    # audit + secrets
    audit_log: str | None = None  # None: audit.default_path()
    credentials_dir: str | None = None
    enrollment_file: str | None = None
    dpapi_entropy_file: str | None = None
    # broker HTTP guard
    bind: str = DEFAULT_BIND
    port: int = DEFAULT_PORT
    allow_non_loopback: bool = False
    allowed_hosts: tuple[str, ...] = ()
    max_request_bytes: int = 256 * 1024
    request_timeout: int = 120
    max_concurrency: int = 64
    require_access_jwt: bool = True
    allowed_service_client_ids: tuple[str, ...] = ()
    cf_access_team_domain: str | None = None
    cf_access_aud: tuple[str, ...] = ()
    allow_service_tokens: bool = False

    @property
    def tls_mode(self) -> str:
        if self.proxmox_tls_fingerprints:
            return "pinned"
        return "insecure" if self.proxmox_insecure_tls else "ca"

    def dangerous_flags(self) -> tuple[str, ...]:
        on = {
            "PROXMOX_INSECURE_TLS": self.proxmox_insecure_tls,
            "MCP_ALLOW_NON_LOOPBACK": self.allow_non_loopback,
            "MCP_ALLOW_SERVICE_TOKENS": self.allow_service_tokens,
            "MCP_ALLOW_ADMIN_TOOLS": self.allow_admin_tools,
            "BROKER_REQUIRE_ACCESS_JWT=0": self.role != "stdio" and not self.require_access_jwt,
        }
        return tuple(name for name in DANGEROUS_FLAGS if on[name])

    def summary(self) -> dict[str, Any]:
        """Every non-secret setting (secrets become a presence flag). Safe to log and audit."""
        # Not dataclasses.asdict: it deep-copies, and SecretStr refuses to be copied.
        out = {f.name: getattr(self, f.name) for f in fields(self)}
        out["proxmox_token_value"] = "<set>" if self.proxmox_token_value else None
        return out

    def config_sha256(self) -> str:
        canonical = json.dumps(self.summary(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---- parsing --------------------------------------------------------------------------


class _Reader:
    def __init__(self, environ: Mapping[str, str]) -> None:
        self.env = environ
        self.problems: list[str] = []

    def raw(self, name: str) -> str | None:
        value = self.env.get(name)
        if value is None or value == "":
            return None
        if value != value.strip() or _BAD_CHARS.search(value):
            self.problems.append(f"{name} has surrounding whitespace or control characters")
            return None
        return value

    def boolean(self, name: str, default: bool) -> bool:
        value = self.raw(name)
        if value is None:
            return default
        if value not in ("0", "1"):
            self.problems.append(f"{name} must be exactly 0 or 1")
            return default
        return value == "1"

    def integer(self, name: str, default: int, lo: int, hi: int) -> int:
        value = self.raw(name)
        if value is None:
            return default
        if not re.fullmatch(r"[0-9]{1,12}", value) or not lo <= int(value) <= hi:
            self.problems.append(f"{name} must be an integer between {lo} and {hi}")
            return default
        return int(value)

    def choice(self, name: str, default: str, options: tuple[str, ...]) -> str:
        value = self.raw(name)
        if value is None:
            return default
        if value not in options:
            self.problems.append(f"{name} must be one of {', '.join(options)}")
            return default
        return value

    def abspath(self, name: str) -> str | None:
        value = self.raw(name)
        if value is None:
            return None
        if not _is_abs(value):
            self.problems.append(f"{name} must be an absolute path")
            return None
        return value

    def csv(self, name: str) -> tuple[str, ...]:
        value = self.raw(name)
        if value is None:
            return ()
        items = tuple(v.strip() for v in value.split(","))
        if any(not v for v in items):
            self.problems.append(f"{name} has an empty list entry")
            return tuple(v for v in items if v)
        return items


def _is_abs(path: str) -> bool:
    # Windows drive paths are absolute even when parsed on POSIX (selfcheck tests).
    return os.path.isabs(path) or bool(re.match(r"^[A-Za-z]:[\\/]", path))


def valid_host(host: str) -> bool:
    """A DNS host name (RFC 1123, <= 253 chars) or an IP literal (IPv6 without brackets)."""
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", host):
        return False  # "300.1.1.1", "10.1" are not hosts
    return bool(_HOSTNAME_RE.match(host))


def parse_fingerprints(value: str) -> tuple[str, ...]:
    """SHA-256 pins ("AB:CD:.." or "abcd..", comma-separated) -> lowercase hex. ValueError."""
    pins = []
    for item in value.split(","):
        hex_ = item.strip().replace(":", "").lower()
        if not _HEX64.match(hex_):
            raise ValueError("PROXMOX_TLS_FINGERPRINT must be SHA-256 hex (64 digits)")
        pins.append(hex_)
    return tuple(pins)


def https_origin(value: str) -> str | None:
    """``https://host`` with no userinfo, port, path, query or fragment, else None."""
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or not valid_host(host)
        or parts.username is not None
        or parts.password is not None
        or port is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        return None
    return f"https://{host}"


def _suggest(name: str) -> str:
    match = difflib.get_close_matches(name, list(KNOWN_VARS), n=1, cutoff=0.75)
    return f" (did you mean {match[0]}?)" if match else ""


def unknown_variables(environ: Mapping[str, str]) -> list[str]:
    """One problem per unknown or removed variable under CHECKED_PREFIXES."""
    problems = []
    for name in sorted(environ):
        if name in REMOVED_VARS:
            problems.append(f"{name}: {REMOVED_VARS[name]}")
        elif name.startswith(CHECKED_PREFIXES) and name not in KNOWN_VARS and name not in FOREIGN_VARS:
            problems.append(f"unknown variable {name}{_suggest(name)}")
    return problems


def load(environ: Mapping[str, str] | None = None, *, role: str = "broker") -> Settings:
    """Parse and validate. Raises ConfigError listing every problem (fail closed)."""
    env = os.environ if environ is None else environ
    if role not in ROLES:
        raise ConfigError([f"unknown role {role!r}"])
    r = _Reader(env)
    r.problems.extend(unknown_variables(env))
    broker = role in ("broker", "selfcheck")

    # -- Proxmox endpoint + TLS
    host = r.raw("PROXMOX_HOST")
    if host is None:
        r.problems.append("PROXMOX_HOST is required")
        host = ""
    elif not valid_host(host):
        r.problems.append("PROXMOX_HOST must be a host name or IP literal (no scheme, port or path)")
    ca_bundle = r.abspath("PROXMOX_CA_BUNDLE")
    if ca_bundle is not None and not os.path.isfile(ca_bundle):
        r.problems.append("PROXMOX_CA_BUNDLE does not name an existing file")
    pins: tuple[str, ...] = ()
    raw_pins = r.raw("PROXMOX_TLS_FINGERPRINT")
    if raw_pins is not None:
        try:
            pins = parse_fingerprints(raw_pins)
        except ValueError as exc:
            r.problems.append(str(exc))
    insecure = r.boolean("PROXMOX_INSECURE_TLS", False)
    if broker and insecure and not pins:
        r.problems.append(
            "PROXMOX_INSECURE_TLS=1 is refused on the broker without PROXMOX_TLS_FINGERPRINT "
            "(an API token must never be sent to an unverified peer)"
        )

    # -- stdio developer identity
    user = r.raw("PROXMOX_USER")
    token_name = r.raw("PROXMOX_TOKEN_NAME")
    token_raw = r.raw("PROXMOX_TOKEN_VALUE")
    token_value = SecretStr(token_raw) if token_raw is not None else None
    del token_raw
    local_mode = r.choice("MCP_LOCAL_MODE", "ro", MODES)
    if broker:
        for name, value in (
            ("PROXMOX_USER", user),
            ("PROXMOX_TOKEN_NAME", token_name),
            ("PROXMOX_TOKEN_VALUE", token_value),
        ):
            if value is not None:
                r.problems.append(
                    f"{name} must not be set on the broker (per-user tokens come from the "
                    "credential store, never the environment)"
                )
        if env.get("MCP_LOCAL_MODE"):
            r.problems.append("MCP_LOCAL_MODE must not be set on the broker (stdio only)")
    else:
        if not (user and token_name and token_value):
            r.problems.append(
                "stdio needs PROXMOX_USER, PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE"
            )
        if user is not None and not _USERID_RE.match(user):
            r.problems.append("PROXMOX_USER must look like user@realm")
        elif user is not None and user.lower() == "root@pam":
            r.problems.append("PROXMOX_USER must not be root@pam; use a dedicated user")
        if token_name is not None and not _TOKEN_NAME_RE.match(token_name):
            r.problems.append("PROXMOX_TOKEN_NAME is not a valid token name")

    # -- policy
    tool_allow = r.csv("MCP_TOOL_ALLOW")
    if any(not _TOOL_RE.match(t) for t in tool_allow):
        r.problems.append("MCP_TOOL_ALLOW must list tool names ([A-Za-z0-9_-]{1,64})")
    tool_deny = r.csv("MCP_TOOL_DENY")
    for pattern in tool_deny:
        try:
            re.compile(pattern)
        except re.error:
            r.problems.append("MCP_TOOL_DENY contains an invalid regular expression")
            break

    # -- secrets + audit
    broker_dir = r.abspath("BROKER_CREDENTIALS_DIR")
    systemd_dir = r.abspath("CREDENTIALS_DIRECTORY")
    if broker_dir and systemd_dir and os.path.normcase(broker_dir) != os.path.normcase(systemd_dir):
        r.problems.append(
            "BROKER_CREDENTIALS_DIR and CREDENTIALS_DIRECTORY name different directories; "
            "set only one"
        )
    credentials_dir = broker_dir or systemd_dir
    enrollment_file = r.abspath("MCP_ENROLLMENT_FILE")
    if enrollment_file is None and credentials_dir:
        enrollment_file = os.path.join(credentials_dir, "enrollment.json")
    if broker and not credentials_dir:
        r.problems.append("BROKER_CREDENTIALS_DIR (or systemd CREDENTIALS_DIRECTORY) is required")

    # -- broker HTTP guard
    port = r.integer("MCP_PORT", DEFAULT_PORT, 1, 65535)
    bind = r.raw("MCP_BIND") or DEFAULT_BIND
    allow_non_loopback = r.boolean("MCP_ALLOW_NON_LOOPBACK", False)
    if bind != "localhost":
        try:
            loopback = ipaddress.ip_address(bind).is_loopback
        except ValueError:
            r.problems.append("MCP_BIND must be an IP literal or localhost")
            loopback = True
        if broker and not loopback and not allow_non_loopback:
            r.problems.append("MCP_BIND is not loopback (MCP_ALLOW_NON_LOOPBACK=1 to override)")
    hosts = tuple(h.lower() for h in r.csv("MCP_ALLOWED_HOSTS")) or tuple(
        h for name in _LOOPBACK_NAMES for h in (name, f"{name}:{port}")
    )
    if any(not _HOST_ENTRY_RE.match(h) for h in hosts):
        r.problems.append("MCP_ALLOWED_HOSTS contains an invalid entry")
    require_jwt = r.boolean("BROKER_REQUIRE_ACCESS_JWT", True)
    client_ids = r.csv("BROKER_ALLOWED_SERVICE_CLIENT_IDS")
    if any(not _CLIENT_ID_RE.match(c) for c in client_ids):
        r.problems.append("BROKER_ALLOWED_SERVICE_CLIENT_IDS contains an invalid entry")
    team = None
    raw_team = r.raw("CF_ACCESS_TEAM_DOMAIN")
    if raw_team is not None:
        team = https_origin(raw_team)
        if team is None:
            r.problems.append("CF_ACCESS_TEAM_DOMAIN must be an https origin (https://<team>...)")
    auds = r.csv("CF_ACCESS_AUD")
    if any(not _AUD_RE.match(a) for a in auds):
        r.problems.append("CF_ACCESS_AUD contains an invalid value")
    if broker and require_jwt:
        for name, value in (
            ("CF_ACCESS_TEAM_DOMAIN", raw_team),
            ("CF_ACCESS_AUD", auds),
            ("BROKER_ALLOWED_SERVICE_CLIENT_IDS", client_ids),
        ):
            if not value:
                r.problems.append(f"{name} is required while BROKER_REQUIRE_ACCESS_JWT=1")

    settings = Settings(
        role=role,
        proxmox_host=host,
        proxmox_port=r.integer("PROXMOX_PORT", DEFAULT_PROXMOX_PORT, 1, 65535),
        proxmox_ca_bundle=ca_bundle,
        proxmox_tls_fingerprints=pins,
        proxmox_insecure_tls=insecure,
        proxmox_read_only=r.boolean("PROXMOX_READ_ONLY", False),
        proxmox_timeout=r.integer("PROXMOX_TIMEOUT", 30, 1, 600),
        proxmox_max_response_bytes=r.integer(
            "PROXMOX_MAX_RESPONSE_BYTES", 64 * 1024 * 1024, 64 * 1024, 1024**3
        ),
        proxmox_user=user,
        proxmox_token_name=token_name,
        proxmox_token_value=token_value,
        local_mode=local_mode,
        tool_mode=r.choice("MCP_TOOL_MODE", "dynamic", TOOL_MODES),
        allow_admin_tools=r.boolean("MCP_ALLOW_ADMIN_TOOLS", False),
        tool_allow=tool_allow,
        tool_deny=tool_deny,
        rate_per_min=r.integer("MCP_RATE_PER_MIN", 60, 1, 10_000),
        rate_per_day=r.integer("MCP_RATE_PER_DAY", 2000, 1, 1_000_000),
        max_result_bytes=r.integer("MCP_MAX_RESULT_BYTES", 2 * 1024 * 1024, 1024, 64 * 1024**2),
        phi_contact=r.boolean("MCP_PHI_CONTACT", False),
        audit_log=r.abspath("MCP_AUDIT_LOG"),
        credentials_dir=credentials_dir,
        enrollment_file=enrollment_file,
        dpapi_entropy_file=r.abspath("BROKER_DPAPI_ENTROPY_FILE"),
        bind=bind,
        port=port,
        allow_non_loopback=allow_non_loopback,
        allowed_hosts=hosts,
        max_request_bytes=r.integer("MCP_MAX_REQUEST_BYTES", 256 * 1024, 1024, 4 * 1024**2),
        request_timeout=r.integer("MCP_REQUEST_TIMEOUT", 120, 5, 900),
        max_concurrency=r.integer("MCP_MAX_CONCURRENCY", 64, 1, 4096),
        require_access_jwt=require_jwt,
        allowed_service_client_ids=client_ids,
        cf_access_team_domain=team,
        cf_access_aud=auds,
        allow_service_tokens=r.boolean("MCP_ALLOW_SERVICE_TOKENS", False),
    )
    if r.problems:
        raise ConfigError(r.problems)
    return settings


# ---- process-wide instance ------------------------------------------------------------

_lock = threading.Lock()
_current: Settings | None = None


def log_dangerous(settings: Settings, logger: logging.Logger | None = None) -> None:
    """One WARNING per dangerous flag. Called on every start; never rate-limited."""
    logger = logger or log
    for flag in settings.dangerous_flags():
        logger.warning("DANGEROUS SETTING %s is active (role %s)", flag, settings.role)


def init(role: str, environ: Mapping[str, str] | None = None) -> Settings:
    """Load, warn about dangerous flags, and install as the process settings."""
    global _current
    settings = load(environ, role=role)
    log_dangerous(settings)
    with _lock:
        _current = settings
    return settings


def current() -> Settings:
    """The installed settings. Fails closed when ``init`` has not run."""
    with _lock:
        if _current is None:
            raise ConfigError(["configuration not initialised (config.init was not called)"])
        return _current


def is_initialised() -> bool:
    with _lock:
        return _current is not None


def audit_start_fields() -> dict[str, Any]:
    """Fields for the audit "start" event; empty before ``init`` (never raises)."""
    with _lock:
        settings = _current
    if settings is None:
        return {}
    return {
        "role": settings.role,
        "dangerous_flags": list(settings.dangerous_flags()),
        "tls_mode": settings.tls_mode,
        "config_sha256": settings.config_sha256(),
    }


def reset_for_tests(settings: Settings | None = None) -> None:
    global _current
    with _lock:
        _current = settings
