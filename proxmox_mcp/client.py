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
  TLS 1.2 minimum. No proxies, no .netrc (trust_env=False), never follows redirects.

Before every request: PROXMOX_READ_ONLY kill switch, outbound.check(method, path,
mode) (path validation + deny list + per-mode allowlist), and a PHI check of
POST/PUT bodies (phi.detect_phi). Every request and every refusal writes one
audit line (side "out", kind "proxmox"): user, token id (not the secret), method,
path, status, deny reason, bytes, ms.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import sys
import time
from typing import Any

import httpcore
import httpx
from dotenv import load_dotenv

from . import audit, outbound, phi
from .credentials import (
    ApiToken,
    CredentialError,
    parse_api_token,
    read_credential,
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
MCP_LOCAL_MODE = os.getenv("MCP_LOCAL_MODE", "ro")

_HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})*|[0-9A-Fa-f:.]{2,45})$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


# --- configuration ------------------------------------------------------------------


def parse_fingerprints(value: str) -> tuple[bytes, ...]:
    """SHA-256 pins from "AB:CD:..." / "abcd..." (comma-separated). ValueError if malformed."""
    pins = []
    for item in value.split(","):
        hex_ = item.strip().replace(":", "").replace(" ", "").lower()
        if not hex_:
            continue
        if not _HEX64.match(hex_):
            raise ValueError("PROXMOX_TLS_FINGERPRINT must be SHA-256 hex (64 digits, colons optional)")
        pins.append(bytes.fromhex(hex_))
    return tuple(pins)


def base_url(host: str, port: str) -> str:
    if not host or not _HOST_RE.match(host):
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
        ctx = ssl.create_default_context(cafile=ca_bundle or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
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


# --- errors -----------------------------------------------------------------------------


def _api_error(response: httpx.Response, body: bytes) -> httpx.HTTPStatusError:
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
    detail = detail[:300]
    message = (
        f"{response.status_code} {response.reason_phrase} for "
        f"{response.request.method} {response.request.url.path}"
    )
    if detail:
        message += f": {detail}"
    return httpx.HTTPStatusError(message, request=response.request, response=response)


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


# --- client -------------------------------------------------------------------------------


class ProxmoxClient:
    def __init__(self) -> None:
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
        self.max_response_bytes = int(PROXMOX_MAX_RESPONSE_BYTES)
        self.client = httpx.AsyncClient(
            transport=GuardedTransport(ssl_context, pins),
            timeout=httpx.Timeout(timeout, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._token_cache: dict[str, tuple[tuple[int, ...], ApiToken]] = {}

    # -- auth ----------------------------------------------------------------------------
    async def authenticate(self) -> None:
        """Kept for the entry points: tokens are resolved per request, nothing to do here."""
        if PROXMOX_PASSWORD:
            logger.warning("PROXMOX_PASSWORD is ignored; password/ticket auth was removed")
        logger.info("Proxmox client ready (per-user API tokens, TLS mode %s)", self.tls_mode)

    def _token_from_credential(self, name: str, expected_userid: str) -> ApiToken:
        st = stat_credential(name)
        key = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
        cached = self._token_cache.get(name)
        if cached is None or cached[0] != key:
            token = parse_api_token(read_credential(name))
            self._token_cache[name] = (key, token)
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
                enrollment.token_credential, enrollment.proxmox_userid
            )
        if enrollment is not None and enrollment.token_credential:
            return enrollment.mode, self._token_from_credential(
                enrollment.token_credential, enrollment.proxmox_userid
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
        method = str(method).upper()
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
        if data:
            # Keys and a hash only: values never reach any audit sink.
            record["arg_keys"] = sorted(str(k) for k in data)
            record["args_sha256"] = audit.canonical_args_hash(data)
        try:
            mode, token = self.resolve_auth(identity)
            record["mode"] = mode
            record["token_id"] = token.token_id
            if PROXMOX_READ_ONLY and method != "GET":
                raise PermissionError(f"Read-only mode (PROXMOX_READ_ONLY): refusing {method}")
            outbound.check(method, path, mode)
            if method in ("POST", "PUT") and data:
                kind = phi.detect_phi(data)
                if kind:
                    raise PermissionError(f"possible PHI detected ({kind})")
        except PermissionError as exc:
            audit.audit_event(**record, status="denied", deny=str(exc), ms=_ms(started))
            raise

        if data is not None:
            # Proxmox API rejects true/false; it requires 1/0.
            data = {k: int(v) if isinstance(v, bool) else v for k, v in data.items()}
        url = f"{base_url(PROXMOX_HOST, PROXMOX_PORT)}{path}"
        headers = {"Authorization": token.header(), "Accept": "application/json"}
        del token
        if method in ("GET", "DELETE"):
            req = self.client.build_request(method, url, headers=headers, params=data)
        else:
            req = self.client.build_request(method, url, headers=headers, data=data)
        del headers

        size = 0
        try:
            response = await self.client.send(req, stream=True, follow_redirects=False)
            try:
                chunks = []
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise ValueError("Proxmox response exceeds PROXMOX_MAX_RESPONSE_BYTES")
                    chunks.append(chunk)
                body = b"".join(chunks)
            finally:
                await response.aclose()
        except Exception as exc:
            audit.audit_event(**record, status="error", error=type(exc).__name__, bytes=size, ms=_ms(started))
            raise
        audit.audit_event(**record, status=response.status_code, bytes=size, ms=_ms(started))
        if response.is_redirect or response.status_code >= 400 or response.status_code < 200:
            raise _api_error(response, body)
        if not body:
            return None
        return json.loads(body)

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
