"""Proxmox VE API client: per-user API tokens, verified TLS, outbound policy, audit.

Authentication: API tokens only.
  Password/ticket auth was removed. A ticket is a full session of the user who
  owns the password (no privilege separation, no per-person attribution when
  shared, 2 h renewal through /access/ticket, which the outbound policy denies),
  and the password itself would have to live on the broker. A privilege-separated
  API token per enrolled person is revocable on its own, scoped by ACL, and named
  in Proxmox's task log (MCP-STD-01 "one person, one key"). PROXMOX_PASSWORD is
  ignored with a warning.

  Per request the token comes from the caller's enrollment
  (enrollment.enrollment_for(identity).token_credential names a credential file,
  see credentials.py); the token's user must equal enrollment.proxmox_userid.
  Parsed tokens are cached per credential name and re-read when the file changes.
  The stdio "local" identity (developer workstation) may instead use
  PROXMOX_USER + PROXMOX_TOKEN_NAME + PROXMOX_TOKEN_VALUE, with mode
  MCP_LOCAL_MODE (default "ro") unless it is enrolled.

TLS (the token is never written to a socket whose peer is not verified):
  - default: chain + hostname verification against PROXMOX_CA_BUNDLE (a PEM file),
    or the OS trust store when unset;
  - PROXMOX_TLS_FINGERPRINT: SHA-256 of the leaf certificate (DER), hex with or
    without colons, comma-separated for rotation. Checked inside the connection
    setup (a wrapped httpcore network backend) right after the TLS handshake and
    before httpcore is handed the stream it writes the request to, so a mismatch
    aborts the connection before a single request byte, let alone the
    Authorization header, is sent. The pre-TLS stream refuses writes outright. With
    a fingerprint and no CA bundle the chain is not validated (the pin replaces it,
    which is what makes self-signed Proxmox certificates usable safely).
  - PROXMOX_INSECURE_TLS=1 disables verification; logged loudly on every start.
  TLS 1.2 minimum, no renegotiation, no session resumption (every connection is a
  full, verified handshake), no SSLKEYLOGFILE. No proxies, no .netrc
  (trust_env=False), never follows redirects, keeps no cookies (one client serves
  every user).

  DNS: PROXMOX_HOST is resolved on every connect, not pinned to one address. The
  binding to the right peer is the TLS check (CA + hostname, or fingerprint), so
  a rebound name reaches a peer that fails it before any byte is written; pinning
  the IP would add nothing in those modes and would break DNS failover. In
  PROXMOX_INSECURE_TLS mode nothing binds the peer; use an IP literal there, and
  the host firewall's program-scoped outbound rule (Proxmox IP:8006 only).

Before every request: PROXMOX_READ_ONLY kill switch, outbound.check(method, path,
mode) (path validation + deny list + per-mode allowlist), strict parameter
encoding (encode_params: scalar values, no control characters, CR/LF only in
free-text fields, 1 MiB cap) and a PHI check of POST/PUT bodies (phi.detect_phi).
Every request and every refusal writes one audit line (side "out", kind
"proxmox"): user, token id (not the secret), method, path, status, deny reason,
bytes, ms.

Responses: Accept-Encoding identity and any other Content-Encoding refused (no
decompression bombs), Content-Length and the streamed raw byte count both capped
by PROXMOX_MAX_RESPONSE_BYTES, and the whole exchange bounded by
PROXMOX_TOTAL_TIMEOUT (a peer trickling bytes defeats a per-read timeout).

Errors never carry the token: exceptions are rebuilt from method + path only
(no headers, no query string), raised outside the except block (no __context__),
after the request object is dropped (no traceback frame holds it), with any
token-shaped text in a peer's error body redacted. httpx's request log line has
its query string removed.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import ssl
import sys
import time
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any
from urllib.parse import urlencode

import anyio
import httpcore
import httpx
from dotenv import load_dotenv

from . import audit, outbound, phi
from .credentials import (
    ApiToken,
    CredentialError,
    parse_api_token,
    read_credential_with_stat,
    stat_credential,
)
from .identity import Identity, require_identity

logger = logging.getLogger("proxmox_mcp.client")

# Load .env before reading the settings below; they are read once, at import time.
load_dotenv()

PROXMOX_HOST = os.getenv("PROXMOX_HOST", "")
PROXMOX_PORT = os.getenv("PROXMOX_PORT", "8006")
PROXMOX_USER = os.getenv("PROXMOX_USER", "")
PROXMOX_TOKEN_NAME = os.getenv("PROXMOX_TOKEN_NAME", "")
PROXMOX_TOKEN_VALUE = os.getenv("PROXMOX_TOKEN_VALUE", "")
PROXMOX_PASSWORD = os.getenv("PROXMOX_PASSWORD", "")
PROXMOX_CA_BUNDLE = os.getenv("PROXMOX_CA_BUNDLE", "")
PROXMOX_TLS_FINGERPRINT = os.getenv("PROXMOX_TLS_FINGERPRINT", "")
PROXMOX_INSECURE_TLS = os.getenv("PROXMOX_INSECURE_TLS", "0").lower() in ("1", "true", "yes")
PROXMOX_READ_ONLY = os.getenv("PROXMOX_READ_ONLY", "false").lower() in ("1", "true", "yes")
PROXMOX_TIMEOUT = os.getenv("PROXMOX_TIMEOUT", "30")
PROXMOX_MAX_RESPONSE_BYTES = os.getenv("PROXMOX_MAX_RESPONSE_BYTES", str(64 * 1024 * 1024))
# Wall-clock cap for one request (connect + send + whole body). The per-read
# timeout alone lets a peer trickle one byte per read forever.
PROXMOX_TOTAL_TIMEOUT = os.getenv("PROXMOX_TOTAL_TIMEOUT", "120")
MCP_LOCAL_MODE = os.getenv("MCP_LOCAL_MODE", "ro")

_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_REQUEST_BODY_BYTES = 1024 * 1024
_PARAM_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
# Free-text fields where Proxmox accepts (and escapes) line breaks. Everywhere
# else CR/LF in a value is refused: Proxmox config files are line-oriented.
_MULTILINE_PARAMS = frozenset(
    {"description", "comment", "notes-template", "body", "ssh-public-keys", "certificates", "input-data"}
)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CRLF_RE = re.compile(r"[\r\n]")
# Token-shaped text that must never leave in an error message.
_TOKEN_TEXT_RE = re.compile(
    r"PVEAPIToken[=: ]\S*|(![A-Za-z][A-Za-z0-9._-]*)=[0-9A-Fa-f]{8}-[0-9A-Fa-f-]{27}", re.IGNORECASE
)


# --- configuration ------------------------------------------------------------------


def parse_fingerprints(value: str) -> tuple[bytes, ...]:
    """SHA-256 pins from "AB:CD:..." / "abcd..." (comma-separated). ValueError if malformed."""
    pins = []
    for item in value.split(","):
        hex_ = item.strip().replace(":", "").replace(" ", "").lower()
        if not hex_:
            continue
        if not _HEX64.fullmatch(hex_):
            raise ValueError("PROXMOX_TLS_FINGERPRINT must be SHA-256 hex (64 digits, colons optional)")
        pins.append(bytes.fromhex(hex_))
    return tuple(pins)


def _valid_host(host: object) -> bool:
    """A DNS name or an IP literal; nothing a URL parser could read as more than a host."""
    if not isinstance(host, str) or not host or len(host) > 253 or not host.isascii():
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return not (isinstance(ip, ipaddress.IPv6Address) and ip.scope_id)
    labels = host.split(".")
    # An all-numeric last label is never a DNS name ("2130706433", "999.1.1.1"):
    # some resolvers read those as IPv4 shorthand.
    return all(_LABEL_RE.fullmatch(label) for label in labels) and not labels[-1].isdigit()


def base_url(host: str, port: str) -> str:
    if not _valid_host(host):
        raise ValueError("PROXMOX_HOST must be a hostname or IP address (no scheme, port or path)")
    try:
        port_n = int(port)
    except ValueError:
        port_n = 0
    if not 0 < port_n < 65536:
        raise ValueError("PROXMOX_PORT must be 1-65535")
    netloc = f"[{host}]" if ":" in host else host
    return f"https://{netloc}:{port_n}/api2/json"


def build_ssl_context(ca_bundle: str, pins: tuple[bytes, ...], insecure: bool) -> ssl.SSLContext:
    if insecure or (pins and not ca_bundle):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        if ca_bundle and not os.path.isfile(ca_bundle):
            raise ValueError("PROXMOX_CA_BUNDLE does not name a readable file")
        # Not ssl.create_default_context(): it honours SSLKEYLOGFILE and would open
        # a key log named by the environment (session keys = every Authorization header).
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # CERT_REQUIRED + check_hostname
        if ca_bundle:
            ctx.load_verify_locations(cafile=ca_bundle)  # the bundle only, no OS store
        else:
            ctx.load_default_certs(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # A TLS 1.2 renegotiation could present a different certificate after the pin
    # check ran on the first one; refuse it outright.
    ctx.options |= ssl.OP_NO_RENEGOTIATION
    ctx.keylog_filename = None  # belt and braces: never a key log
    return ctx


def validate_config() -> None:
    """Raise ValueError on unusable configuration (host, port, TLS settings)."""
    base_url(PROXMOX_HOST, PROXMOX_PORT)
    build_ssl_context(PROXMOX_CA_BUNDLE, parse_fingerprints(PROXMOX_TLS_FINGERPRINT), PROXMOX_INSECURE_TLS)
    if MCP_LOCAL_MODE not in outbound.MODES:
        raise ValueError("MCP_LOCAL_MODE must be ro, operator or rw")


def _validate_config() -> None:
    """Entry-point check: print the problem and exit 1 (no secrets in the message)."""
    try:
        validate_config()
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    if PROXMOX_PASSWORD:
        print("Warning: PROXMOX_PASSWORD is ignored; use an API token", file=sys.stderr)


# --- TLS guard: verify the peer before any byte of the request is written --------------


class TLSVerificationError(httpcore.ConnectError):
    pass


def _check_peer(stream: httpcore.AsyncNetworkStream, pins: tuple[bytes, ...]) -> None:
    ssl_object = stream.get_extra_info("ssl_object")
    if ssl_object is None:
        raise TLSVerificationError("TLS was not established")
    if ssl_object.version() not in ("TLSv1.2", "TLSv1.3"):
        raise TLSVerificationError("TLS version too old")
    if ssl_object.session_reused:
        # No code path offers a session; a resumed one would skip the checks below.
        raise TLSVerificationError("TLS session resumption is not accepted")
    if pins:
        der = ssl_object.getpeercert(binary_form=True)
        digest = hashlib.sha256(der).digest() if der else b""
        if not any(hmac.compare_digest(digest, pin) for pin in pins):
            raise TLSVerificationError("TLS certificate fingerprint mismatch")


class _GuardedStream(httpcore.AsyncNetworkStream):
    """A TCP stream that may only be used after a verified TLS handshake."""

    def __init__(self, inner: httpcore.AsyncNetworkStream, pins: tuple[bytes, ...]) -> None:
        self._inner = inner
        self._pins = pins

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        raise TLSVerificationError("refusing plaintext read")

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        raise TLSVerificationError("refusing to send before TLS verification")

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        tls = await self._inner.start_tls(ssl_context, server_hostname, timeout)
        try:
            _check_peer(tls, self._pins)
        except BaseException:
            await tls.aclose()
            raise
        return tls

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class GuardedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, pins: tuple[bytes, ...], inner: httpcore.AsyncNetworkBackend | None = None):
        self._pins = pins
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        stream = await self._inner.connect_tcp(
            host, port, timeout=timeout, local_address=local_address, socket_options=socket_options
        )
        return _GuardedStream(stream, self._pins)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise TLSVerificationError("unix sockets are not used")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool uses GuardedBackend (HTTP/1.1, no proxy)."""

    def __init__(self, ssl_context: ssl.SSLContext, pins: tuple[bytes, ...]) -> None:
        limits = httpx.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=30)
        super().__init__(verify=ssl_context, trust_env=False, http1=True, http2=False, limits=limits)
        # httpx does not expose network_backend; rebuild its pool with ours. Fail
        # closed if a future httpx stops using this attribute.
        if not isinstance(getattr(self, "_pool", None), httpcore.AsyncConnectionPool):
            raise RuntimeError("unsupported httpx version: cannot install TLS guard")
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=True,
            http2=False,
            retries=0,
            network_backend=GuardedBackend(pins),
        )


# --- logging hygiene ----------------------------------------------------------------------


class _DropQuery(logging.Filter):
    """httpx logs "HTTP Request: GET <url>" at INFO; the query string can carry values."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple) and record.args:
            record.args = tuple(
                str(a).split("?", 1)[0] if isinstance(a, httpx.URL) else a for a in record.args
            )
        return True


_httpx_logger = logging.getLogger("httpx")
if not any(isinstance(f, _DropQuery) for f in _httpx_logger.filters):
    _httpx_logger.addFilter(_DropQuery())


# --- request encoding -------------------------------------------------------------------------


def _invalid(key: str | None = None) -> PermissionError:
    suffix = f" {key}" if key else ""
    return PermissionError(f"blocked by outbound policy: invalid request parameter{suffix}")


def _scalar(key: str, value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"  # Proxmox rejects true/false
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _invalid(key)
        return repr(value)
    if isinstance(value, str):
        if _CTRL_RE.search(value) or (key not in _MULTILINE_PARAMS and _CRLF_RE.search(value)):
            raise _invalid(key)
        return value
    raise _invalid(key)


def encode_params(data: Any) -> list[tuple[str, str]]:
    """Flatten tool arguments into (name, value) pairs for a query string or form body.

    Strict: names are Proxmox parameter names, values are scalars or flat lists of
    scalars (sent as repeated names), None means "not set" and is dropped. Nested
    structures, bytes, NaN/inf and control characters are refused, so nothing
    reaches the wire that the caller did not literally mean. Errors name the key,
    never the value.
    """
    if data is None:
        return []
    if not isinstance(data, dict):
        raise _invalid()
    pairs: list[tuple[str, str]] = []
    for key, value in data.items():
        if not isinstance(key, str) or not _PARAM_NAME_RE.fullmatch(key):
            raise _invalid()
        if value is None:
            continue
        if isinstance(value, list | tuple):
            for item in value:
                if item is None or isinstance(item, list | tuple | dict):
                    raise _invalid(key)
                pairs.append((key, _scalar(key, item)))
        else:
            pairs.append((key, _scalar(key, value)))
    if len(urlencode(pairs)) > MAX_REQUEST_BODY_BYTES:
        raise PermissionError("blocked by outbound policy: request parameters too large")
    return pairs


# --- errors (never carry the Authorization header, the token, or the query string) ----------


def _scrub_token(text: str) -> str:
    return _TOKEN_TEXT_RE.sub(lambda m: f"{m.group(1)}=<redacted>" if m.group(1) else "<redacted>", text)


def _scrub(text: str) -> str:
    """Error text: no URLs (query strings carry values), no token-shaped text."""
    return _scrub_token(re.sub(r"https?://\S+", "<url>", text))


def _bare_request(method: str, path: str) -> httpx.Request:
    """A stand-in request for exceptions: no headers, no query, no body."""
    return httpx.Request(method if method in outbound.METHODS else "GET", f"{base_url(PROXMOX_HOST, PROXMOX_PORT)}{path}")


def _api_error(status: int, content_type: str, body: bytes, method: str, path: str) -> httpx.HTTPStatusError:
    """An HTTPStatusError that keeps the reason Proxmox gives in the response body."""
    detail = ""
    try:
        parsed = json.loads(body) if body else None
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        errors = parsed.get("errors")
        if isinstance(errors, dict) and errors:
            detail = "; ".join(f"{k}: {str(v).strip()}" for k, v in errors.items())
        elif parsed.get("message"):
            detail = str(parsed["message"]).strip()
    elif body:
        detail = body.decode("utf-8", "replace").strip()
    detail = _scrub(detail[:300])
    text = body.decode("utf-8", "replace")
    if _TOKEN_TEXT_RE.search(text):
        body = _scrub_token(text).encode("utf-8")  # a peer echoing the token gets it back redacted
    request = _bare_request(method, path)
    headers = {"Content-Type": content_type} if content_type else {}
    response = httpx.Response(status, headers=headers, content=body, request=request)
    message = f"{status} {response.reason_phrase} for {method} /api2/json{path}"
    if detail:
        message += f": {detail}"
    return httpx.HTTPStatusError(message, request=request, response=response)


class _ResponseRefused(ValueError):
    """Our own refusal of a response (size cap, encoding); the message is fixed text."""


def _sanitize(exc: Exception, method: str, path: str) -> Exception:
    """A fresh exception with the same meaning and no reference to the sent request."""
    if isinstance(exc, TimeoutError):
        return httpx.TimeoutException(
            "Proxmox request exceeded PROXMOX_TOTAL_TIMEOUT", request=_bare_request(method, path)
        )
    if isinstance(exc, httpx.TransportError):
        try:
            return type(exc)(_scrub(str(exc)), request=_bare_request(method, path))
        except Exception:
            return httpx.TransportError(type(exc).__name__, request=_bare_request(method, path))
    if isinstance(exc, _ResponseRefused):
        return ValueError(str(exc))
    return httpx.TransportError(f"Proxmox request failed ({type(exc).__name__})", request=_bare_request(method, path))


async def _aiter(chunks: Any) -> Any:
    if isinstance(chunks, list):
        for chunk in chunks:
            yield chunk
    else:
        async for chunk in chunks:
            yield chunk


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _stat_key(st: os.stat_result) -> tuple[int, ...]:
    # ctime cannot be set from user space, so restoring mtime after a swap does not help.
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


# --- client -------------------------------------------------------------------------------


class ProxmoxClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        pins = parse_fingerprints(PROXMOX_TLS_FINGERPRINT)
        ssl_context = build_ssl_context(PROXMOX_CA_BUNDLE, pins, PROXMOX_INSECURE_TLS)
        if PROXMOX_INSECURE_TLS:
            logger.warning(
                "PROXMOX_INSECURE_TLS=1: Proxmox TLS certificate verification is DISABLED%s. "
                "API tokens can be intercepted. Set PROXMOX_CA_BUNDLE or PROXMOX_TLS_FINGERPRINT.",
                " (fingerprint pin still enforced)" if pins else "",
            )
        self.tls_mode = (
            "insecure" if PROXMOX_INSECURE_TLS and not pins
            else "pinned" if pins else "ca"
        )
        try:
            timeout = float(PROXMOX_TIMEOUT)
        except ValueError:
            timeout = 30.0
        try:
            self.total_timeout = float(PROXMOX_TOTAL_TIMEOUT)
        except ValueError:
            self.total_timeout = 120.0
        self.max_response_bytes = int(PROXMOX_MAX_RESPONSE_BYTES)
        self.client = httpx.AsyncClient(
            # The transport argument exists for offline tests; production always
            # gets the guarded, pinned transport.
            transport=transport or GuardedTransport(ssl_context, pins),
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=False,
            trust_env=False,
            # One client serves every user: a cookie set in one user's response must
            # never ride along on another's request. This jar accepts no cookie.
            cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
        )
        self._token_cache: dict[str, tuple[tuple[int, ...], ApiToken]] = {}
        # credential name -> the one subject allowed to use it ("one person, one key").
        self._credential_owner: dict[str, str] = {}

    # -- auth ----------------------------------------------------------------------------
    async def authenticate(self) -> None:
        """Kept for the entry points: tokens are resolved per request, nothing to do here."""
        if PROXMOX_PASSWORD:
            logger.warning("PROXMOX_PASSWORD is ignored; password/ticket auth was removed")
        logger.info("Proxmox client ready (per-user API tokens, TLS mode %s)", self.tls_mode)

    def _token_from_credential(self, name: str, expected_userid: str, subject: str) -> ApiToken:
        owner = self._credential_owner.setdefault(name, subject)
        if owner != subject:
            raise CredentialError(f"credential {name!r} is bound to another enrolled user")
        cached = self._token_cache.get(name)
        if cached is None or cached[0] != _stat_key(stat_credential(name)):
            # Key the cache by the file actually read (fstat of the open fd), not by a
            # separate stat: a swap between the two would otherwise pin the wrong token.
            text, st = read_credential_with_stat(name)
            token = parse_api_token(text)
            del text
            self._token_cache[name] = (_stat_key(st), token)
        else:
            token = cached[1]
        if token.userid != expected_userid:
            raise CredentialError("API token belongs to a different Proxmox user than the enrollment")
        return token

    @staticmethod
    def _env_token() -> ApiToken:
        if not (PROXMOX_USER and PROXMOX_TOKEN_NAME and PROXMOX_TOKEN_VALUE):
            raise CredentialError(
                "no API token for the local identity "
                "(set PROXMOX_USER, PROXMOX_TOKEN_NAME, PROXMOX_TOKEN_VALUE)"
            )
        return parse_api_token(f"{PROXMOX_USER}!{PROXMOX_TOKEN_NAME}={PROXMOX_TOKEN_VALUE}")

    def resolve_auth(self, identity: Identity) -> tuple[str, ApiToken]:
        """(mode, token) for the caller. Raises PermissionError (fail closed)."""
        try:
            from . import enrollment as enrollment_mod
        except ImportError:
            enrollment_mod = None
        enrollment = None
        if enrollment_mod is not None:
            try:
                enrollment = enrollment_mod.enrollment_for(identity)
            except PermissionError:
                if identity.kind != "local":
                    raise
        if identity.kind != "local":
            if enrollment is None:
                raise PermissionError("not enrolled")
            if not enrollment.token_credential:
                raise PermissionError("enrollment has no token credential")
            return enrollment.mode, self._token_from_credential(
                enrollment.token_credential, enrollment.proxmox_userid, identity.subject
            )
        if enrollment is not None and enrollment.token_credential:
            return enrollment.mode, self._token_from_credential(
                enrollment.token_credential, enrollment.proxmox_userid, identity.subject
            )
        mode = enrollment.mode if enrollment is not None else MCP_LOCAL_MODE
        if mode not in outbound.MODES:
            raise PermissionError("invalid MCP_LOCAL_MODE")
        return mode, self._env_token()

    # -- requests --------------------------------------------------------------------------
    async def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
    ) -> Any:
        # ASCII before upper(): "poſt".upper() == "POST".
        method = method.upper() if isinstance(method, str) and method.isascii() else "?"
        started = time.monotonic()
        identity = require_identity()
        record: dict[str, Any] = {
            "side": "out",
            "kind": "proxmox",
            "user": identity.subject,
            "ray": identity.ray_id,
            "method": method,
            "path": path,
        }
        if data and isinstance(data, dict):
            # Keys and a hash only: values never reach any audit sink.
            record["arg_keys"] = sorted(str(k) for k in data)
            try:
                record["args_sha256"] = audit.canonical_args_hash(data)
            except (TypeError, ValueError):
                record["args_sha256"] = None  # unhashable keys; encode_params refuses them
        try:
            mode, token = self.resolve_auth(identity)
            record["mode"] = mode
            record["token_id"] = token.token_id
            if PROXMOX_READ_ONLY and method != "GET":
                raise PermissionError(f"Read-only mode (PROXMOX_READ_ONLY): refusing {method}")
            outbound.check(method, path, mode)
            pairs = encode_params(data)
            if method in ("POST", "PUT") and data:
                kind = phi.detect_phi(data)
                if kind:
                    raise PermissionError(f"possible PHI detected ({kind})")
        except PermissionError as exc:
            audit.audit_event(**record, status="denied", deny=str(exc), ms=_ms(started))
            raise

        # The header travels in a box the exchange empties, so no frame of this
        # call chain still references the secret while the request is in flight.
        box = [token.header()]
        del token
        meter = [0]
        try:
            status, content_type, body = await self._exchange(method, path, pairs, box, meter)
        except Exception as exc:
            audit.audit_event(**record, status="error", error=type(exc).__name__, bytes=meter[0], ms=_ms(started))
            raise
        audit.audit_event(**record, status=status, bytes=meter[0], ms=_ms(started))
        if status >= 300 or status < 200:
            error = _api_error(status, content_type, body, method, path)
            del body  # the raw body may echo request data; only the scrubbed copy travels
            raise error
        if not body:
            return None
        try:
            return json.loads(body)
        except ValueError:
            pass
        # Raised outside the except block: no __context__ holding the body.
        raise ValueError("Proxmox returned a response that is not JSON")

    async def _exchange(
        self, method: str, path: str, pairs: list[tuple[str, str]], box: list[str], meter: list[int]
    ) -> tuple[int, str, bytes]:
        """Send one request and read the raw body under the size cap and deadline.

        Any failure is re-raised as a fresh exception built from method + path only,
        raised outside the except block, after the request object is dropped: no
        exception, __context__ or traceback frame reaches the Authorization header.
        """
        url = f"{base_url(PROXMOX_HOST, PROXMOX_PORT)}{path}"
        headers = {
            "Authorization": box.pop(),
            "Accept": "application/json",
            # Never let the peer pick a decoder (gzip/deflate/br/zstd bombs): we ask
            # for identity and refuse anything else below.
            "Accept-Encoding": "identity",
        }
        if method in ("GET", "DELETE"):
            req = self.client.build_request(method, url, headers=headers, params=pairs or None)
        elif pairs:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            req = self.client.build_request(method, url, headers=headers, content=urlencode(pairs).encode("ascii"))
        else:
            req = self.client.build_request(method, url, headers=headers)
        del headers
        error: Exception | None = None
        status, content_type, chunks = 0, "", []
        try:
            with anyio.fail_after(self.total_timeout):
                response = await self.client.send(req, stream=True, follow_redirects=False)
                try:
                    status = response.status_code
                    content_type = response.headers.get("Content-Type", "")
                    encoding = response.headers.get("Content-Encoding", "").strip().lower()
                    if encoding not in ("", "identity"):
                        raise _ResponseRefused("Proxmox response has an unsupported Content-Encoding")
                    declared = response.headers.get("Content-Length", "")
                    if declared.isdigit() and int(declared) > self.max_response_bytes:
                        raise _ResponseRefused("Proxmox response exceeds PROXMOX_MAX_RESPONSE_BYTES")
                    # The network transport always streams; a transport that hands back an
                    # already-read body (httpx.MockTransport) is measured the same way.
                    raw = [response.content] if response.is_stream_consumed else response.aiter_raw()
                    async for chunk in _aiter(raw):
                        meter[0] += len(chunk)
                        if meter[0] > self.max_response_bytes:
                            raise _ResponseRefused("Proxmox response exceeds PROXMOX_MAX_RESPONSE_BYTES")
                        chunks.append(chunk)
                finally:
                    await response.aclose()
                    del response
        except Exception as exc:
            error = _sanitize(exc, method, path)
        del req
        if error is not None:
            raise error
        return status, content_type, b"".join(chunks)

    async def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("GET", path, params)

    async def post(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return await self.request("POST", path, data)

    async def put(self, path: str, data: dict[str, Any] | None = None) -> Any:
        return await self.request("PUT", path, data)

    async def delete(self, path: str, params: dict[str, Any] | None = None) -> Any:
        return await self.request("DELETE", path, params)

    async def close(self) -> None:
        await self.client.aclose()
