"""On-prem broker HTTP API (``proxmox-mcp-http``) with the in-process guard.

The Cloudflare Worker speaks MCP to Claude and calls this broker for the two
things that need Proxmox credentials or the final policy decision:

    GET  /healthz       200 "ok"; no auth, no information
    GET  /v1/catalog    tools the asserted user may run: {"mode", "tools": [...]}
    POST /v1/execute    {"tool": str, "arguments": {...}} -> {"ok": bool, "text": str}

The broker listens on loopback only; cloudflared (Workers VPC service binding,
or a tunnel hostname behind an Access app whose only policy is the Worker's
service token) is the only intended client. Nothing here trusts that. Every
/v1 request passes, in this order:

    1. framing + size     Content-Length digits only, no Transfer-Encoding
                          but chunked and never with Content-Length, no
                          Content-Encoding (the body hash is over wire bytes)  -> 400 / 415
                          MCP_MAX_REQUEST_BYTES (default 256 KiB)             -> 413
                          raw request target must equal the decoded route     -> 404
    2. Host allowlist     MCP_ALLOWED_HOSTS (DNS rebinding); any Origin       -> 400 / 421 / 403
    (the identity assertion, layer 4, is mandatory in every mode; no setting turns it off)
    3. Access JWT         Cf-Access-Jwt-Assertion, a service token whose
                          common_name is in BROKER_ALLOWED_SERVICE_CLIENT_IDS;
                          required unless BROKER_REQUIRE_ACCESS_JWT=0         -> 401 / 503
    4. identity           X-MCP-Identity, Ed25519 JWS from the Worker, bound to
                          this body, method and path, single use              -> 401
                          (headers are checked BEFORE the body is read, and the
                          body must arrive within MCP_BODY_TIMEOUT)           -> 408
    5. enrollment         the asserted user must be enrolled here             -> 403
       request rate       coarse per-user cap on all /v1 traffic              -> 429
    6. endpoint           identity bound for the request (scope + ContextVar)

The Access service-token identity proves *which client* is calling (the
Worker); it is never treated as the user. The user is only ever the ``sub`` of
a verified identity assertion, and mode/tier authority stays here: the Worker's
filtering is a first gate, this broker is final. /v1/execute runs the same
pipeline as an MCP execute_tool (server.run_tool): rate limit, policy, schema,
audit, handler, output rendering.

Why no MCP transport here: the Worker is stateless per request and needs only
catalog and execute; a two-endpoint JSON API is a smaller surface than
Streamable HTTP (no sessions, no SSE, no JSON-RPC method space to police).

Logging never includes tokens, assertions or full header sets. Portable: no
POSIX-only calls (runs as a Windows service on the broker host).
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import os
import re
import sys
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import anyio
from starlette.applications import Starlette
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..identity import Identity, current_identity
from . import IDENTITY_SCOPE_KEY
from .access_jwt import (
    JWT_HEADER,
    AccessConfigError,
    AccessDenied,
    AccessUnavailable,
    AccessVerifier,
)
from .identity_assertion import (
    HEADER as ASSERTION_HEADER,
)
from .identity_assertion import (
    AssertionConfigError,
    AssertionDenied,
    IdentityAssertionVerifier,
)
from .ratelimit import RateLimited, RateLimiter

log = logging.getLogger("proxmox_mcp.http")

HEALTH_PATH = "/healthz"
CATALOG_PATH = "/v1/catalog"
EXECUTE_PATH = "/v1/execute"
ROUTES = {CATALOG_PATH: "GET", EXECUTE_PATH: "POST"}
CORRELATION_SCOPE_KEY = "proxmox_mcp.correlation"

DEFAULT_MAX_REQUEST_BYTES = 256 * 1024
DEFAULT_PORT = 8765
DEFAULT_BIND = "127.0.0.1"
# Request head budget. The Access JWT (<= 8 KiB) and the identity assertion
# (<= 4 KiB) are the large ones; cloudflared adds a couple of dozen small headers.
MAX_HEADER_BYTES = 32 * 1024
MAX_HEADER_COUNT = 100

SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"cache-control", b"no-store"),
    (b"pragma", b"no-cache"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-resource-policy", b"same-origin"),
)
_SECURITY_HEADER_NAMES = frozenset(name for name, _ in SECURITY_HEADERS) | {b"server"}
_HOST_ENTRY_RE = re.compile(r"[a-z0-9.-]+(:[0-9]{1,5})?|\[[0-9a-f:.]+\](:[0-9]{1,5})?")
# All matched with fullmatch: a `$` anchor also matches before a trailing newline.
_TOOL_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_RAY_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
# Digits only (str.isdigit() accepts e.g. U+00B2), and short enough for int().
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,12}")
_LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")
_TRUE = {"1", "true", "yes"}
_FALSE = {"0", "false", "no"}
_UNAUTHORIZED_HEADERS = [(b"www-authenticate", b"Bearer")]


class ConfigError(RuntimeError):
    """The broker is not configured; refuse to start."""


def _env_int(name: str, default: int, *, lo: int, hi: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    raise ConfigError(f"{name} must be 1 or 0")


def _csv(name: str) -> tuple[str, ...]:
    return tuple(v.strip().lower() for v in os.getenv(name, "").split(",") if v.strip())


@dataclass(frozen=True)
class HttpSettings:
    allowed_hosts: tuple[str, ...]
    require_access_jwt: bool = True
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    request_timeout: float = 120.0
    # The whole request body must arrive within this many seconds (slow-body
    # slowloris). cloudflared sends a <= 256 KiB body in one go.
    body_timeout: float = 15.0
    # The request line and headers must arrive within this many seconds.
    header_timeout: float = 10.0
    bind: str = DEFAULT_BIND
    port: int = DEFAULT_PORT
    max_concurrency: int = 64

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            raise ConfigError("MCP_ALLOWED_HOSTS is not set")
        for host in self.allowed_hosts:
            if not _HOST_ENTRY_RE.fullmatch(host):
                raise ConfigError("MCP_ALLOWED_HOSTS contains an invalid entry")

    @classmethod
    def from_env(cls) -> HttpSettings:
        port = _env_int("MCP_PORT", DEFAULT_PORT, lo=1, hi=65535)
        # Default: loopback names only. Workers VPC mode sends the BROKER_URL host
        # (e.g. broker.internal) and the tunnel fallback the public broker hostname;
        # both must be listed explicitly.
        hosts = _csv("MCP_ALLOWED_HOSTS") or tuple(
            h for name in _LOOPBACK_NAMES for h in (name, f"{name}:{port}")
        )
        return cls(
            allowed_hosts=hosts,
            require_access_jwt=_env_bool("BROKER_REQUIRE_ACCESS_JWT", True),
            max_request_bytes=_env_int(
                "MCP_MAX_REQUEST_BYTES", DEFAULT_MAX_REQUEST_BYTES, lo=1024, hi=4 * 1024 * 1024
            ),
            request_timeout=float(_env_int("MCP_REQUEST_TIMEOUT", 120, lo=5, hi=900)),
            body_timeout=float(_env_int("MCP_BODY_TIMEOUT", 15, lo=1, hi=300)),
            header_timeout=float(_env_int("MCP_HEADER_TIMEOUT", 10, lo=1, hi=120)),
            bind=os.getenv("MCP_BIND", DEFAULT_BIND).strip() or DEFAULT_BIND,
            port=port,
            max_concurrency=_env_int("MCP_MAX_CONCURRENCY", 64, lo=1, hi=4096),
        )


def check_bind(bind: str) -> None:
    """Refuse a non-loopback bind unless MCP_ALLOW_NON_LOOPBACK=1."""
    if bind == "localhost":
        return
    try:
        loopback = ipaddress.ip_address(bind).is_loopback
    except ValueError:
        loopback = False  # a hostname could resolve anywhere
    if not loopback and os.getenv("MCP_ALLOW_NON_LOOPBACK", "").strip().lower() not in _TRUE:
        raise ConfigError(
            f"refusing to bind {bind!r}: not loopback (set MCP_ALLOW_NON_LOOPBACK=1 to override)"
        )


# ---- raw ASGI helpers ---------------------------------------------------


AUDIT_SCOPE_KEY = "proxmox_mcp.audit_notes"


def _note(scope: Scope, **fields: Any) -> None:
    """Record why a request was refused (or who it was) for the broker audit line."""
    scope.setdefault(AUDIT_SCOPE_KEY, {}).update({k: v for k, v in fields.items() if v})


def _header(scope: Scope, name: bytes) -> str | None:
    """The single value of header ``name``; None if absent. Repeats raise ValueError."""
    found: bytes | None = None
    for key, value in scope.get("headers", ()):
        if key.lower() == name:
            if found is not None:
                raise ValueError("repeated header")
            found = value
    return None if found is None else found.decode("latin-1")


async def _send_body(
    send: Send, status: int, payload: bytes, content_type: bytes, headers: list | None = None
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type),
                (b"content-length", str(len(payload)).encode()),
                *(headers or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


async def _send_json(
    send: Send, status: int, body: dict[str, Any], headers: list | None = None
) -> None:
    payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
    await _send_body(send, status, payload, b"application/json", headers)


class _BodyTooLarge(Exception):
    pass


# ---- guard layers (pure ASGI, outermost first) ---------------------------


class SecurityHeaders:
    """Adds the fixed security headers to every response (replacing any duplicates)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                kept = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in _SECURITY_HEADER_NAMES
                ]
                message = {**message, "headers": [*kept, *SECURITY_HEADERS]}
            await send(message)

        await self.app(scope, receive, send_with_headers)


class RequestSizeCap:
    """Layer 1: refuse bodies over the cap, by Content-Length and while streaming."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            length = _header(scope, b"content-length")
            transfer = _header(scope, b"transfer-encoding")
            encoding = _header(scope, b"content-encoding")
        except ValueError:
            await _send_json(send, 400, {"error": "bad request"})
            return
        # The server (h11) already enforces most of this; repeat it here so the
        # guard does not depend on which HTTP parser sits in front of it.
        if length is not None and not _CONTENT_LENGTH_RE.fullmatch(length):
            await _send_json(send, 400, {"error": "bad request"})
            return
        if transfer is not None and (length is not None or transfer.strip().lower() != "chunked"):
            await _send_json(send, 400, {"error": "bad request"})
            return
        if encoding is not None and encoding.strip().lower() != "identity":
            # Never inflate: the identity assertion hashes the bytes on the wire,
            # and a decompressor is an amplification surface.
            await _send_json(send, 415, {"error": "unsupported media type"})
            return
        if length is not None and int(length) > self.max_bytes:
            await _send_json(send, 413, {"error": "request too large"})
            return

        seen = 0
        started = False

        async def counting_receive() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _BodyTooLarge:
            if not started:
                await _send_json(send, 413, {"error": "request too large"})


class HostCheck:
    """Layer 2: Host allowlist (DNS rebinding). The broker has no browser clients,
    so any request carrying an Origin header is refused."""

    def __init__(self, app: ASGIApp, allowed_hosts: tuple[str, ...]) -> None:
        self.app = app
        self.allowed_hosts = frozenset(allowed_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            host = _header(scope, b"host")
            origin = _header(scope, b"origin")
        except ValueError:
            await _send_json(send, 400, {"error": "bad request"})
            return
        if not host:
            await _send_json(send, 400, {"error": "bad request"})
            return
        if host.strip().lower() not in self.allowed_hosts:
            await _send_json(send, 421, {"error": "misdirected request"})
            return
        if origin is not None:
            await _send_json(send, 403, {"error": "forbidden"})
            return
        await self.app(scope, receive, send)


EnrollmentCheck = Callable[[Identity], Any]
Endpoint = Callable[[Scope, bytes, Send], Any]


def _default_enrollment_check(identity: Identity) -> Any:
    from ..enrollment import enrollment_for

    return enrollment_for(identity)


async def _read_body(receive: Receive) -> bytes | None:
    """The whole request body (already size-capped), or None if the client left."""
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return None
        if message["type"] != "http.request":
            continue
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            return b"".join(chunks)


class BrokerAuth:
    """Layers 3-6: Access service token, identity assertion, enrollment, rate, binding."""

    def __init__(
        self,
        endpoint: Endpoint,
        *,
        assertion_verifier: IdentityAssertionVerifier,
        access_verifier: AccessVerifier | None,
        enrollment_check: EnrollmentCheck = _default_enrollment_check,
        request_limiter: RateLimiter | None = None,
        body_timeout: float = 15.0,
    ) -> None:
        self.endpoint = endpoint
        self.body_timeout = body_timeout
        self.assertion_verifier = assertion_verifier
        self.access_verifier = access_verifier
        self.enrollment_check = enrollment_check
        self.request_limiter = request_limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Everything that does not need the body is checked first, so an
        # unauthenticated client cannot make the broker wait for or buffer one.
        try:
            access_token = _header(scope, JWT_HEADER.encode())
            assertion = _header(scope, ASSERTION_HEADER.encode())
            ray = _header(scope, b"cf-ray")
        except ValueError:
            _note(scope, deny="repeated auth header")
            await _send_json(send, 401, {"error": "unauthorized"}, _UNAUTHORIZED_HEADERS)
            return
        ray_id = ray if ray is not None and _RAY_RE.fullmatch(ray) else None
        correlation: dict[str, Any] = {}

        if self.access_verifier is not None:
            try:
                service = await self.access_verifier.authenticate(access_token, ray_id=ray_id)
            except AccessDenied as exc:
                log.info("access denied: %s (ray=%s)", exc.reason, ray_id)
                _note(scope, deny=f"access jwt: {exc.reason}")
                await _send_json(send, 401, {"error": "unauthorized"}, _UNAUTHORIZED_HEADERS)
                return
            except AccessUnavailable:
                log.error("access keys unavailable; refusing request (ray=%s)", ray_id)
                _note(scope, deny="access keys unavailable")
                await _send_json(send, 503, {"error": "unavailable"}, [(b"retry-after", b"30")])
                return
            correlation["svc"] = service.subject
            _note(scope, svc=service.subject)

        if not assertion:
            log.info("identity assertion refused: missing assertion (ray=%s)", ray_id)
            _note(scope, deny="identity assertion missing")
            await _send_json(send, 401, {"error": "unauthorized"}, _UNAUTHORIZED_HEADERS)
            return
        try:
            with anyio.fail_after(self.body_timeout):
                body = await _read_body(receive)
        except TimeoutError:
            log.info("request body not received within %ss (ray=%s)", self.body_timeout, ray_id)
            _note(scope, deny="body timeout")
            await _send_json(send, 408, {"error": "request timeout"}, [(b"connection", b"close")])
            return
        if body is None:
            return

        try:
            verified = self.assertion_verifier.verify(
                assertion, body=body, method=scope["method"], path=scope["path"]
            )
        except AssertionDenied as exc:
            log.info("identity assertion refused: %s (ray=%s)", exc.reason, ray_id)
            _note(scope, deny=f"identity assertion: {exc.reason}")
            await _send_json(send, 401, {"error": "unauthorized"}, _UNAUTHORIZED_HEADERS)
            return
        identity = verified.identity
        correlation["jti"] = verified.jti
        _note(scope, user=identity.subject, jti=verified.jti)

        try:
            self.enrollment_check(identity)
        except Exception as exc:  # PermissionError("not enrolled"), or anything else: deny
            log.info("not enrolled: %s (%s)", identity.subject, type(exc).__name__)
            _note(scope, deny="not enrolled")
            await _send_json(send, 403, {"error": "forbidden"})
            return

        if self.request_limiter is not None:
            try:
                self.request_limiter.hit(identity.subject)
            except RateLimited as exc:
                _note(scope, deny="rate limited")
                await _send_json(
                    send, 429, {"ok": False, "text": exc.reason}, [(b"retry-after", b"60")]
                )
                return

        scope[IDENTITY_SCOPE_KEY] = identity
        scope[CORRELATION_SCOPE_KEY] = correlation
        token = current_identity.set(identity)
        try:
            await self.endpoint(scope, body, send)
        finally:
            current_identity.reset(token)


# ---- endpoints -----------------------------------------------------------


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _no_constants(_: str) -> Any:
    raise ValueError("non-finite number")


def parse_execute_body(body: bytes) -> tuple[str, dict[str, Any]] | None:
    """(tool, arguments) from a strict {"tool", "arguments"} object, else None."""
    try:
        doc = json.loads(
            body.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constants
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or not set(doc) <= {"tool", "arguments"}:
        return None
    tool = doc.get("tool")
    arguments = doc.get("arguments", {})
    if not isinstance(tool, str) or not _TOOL_RE.fullmatch(tool) or not isinstance(arguments, dict):
        return None
    return tool, arguments


async def catalog_endpoint(scope: Scope, body: bytes, send: Send) -> None:
    from .. import server

    identity: Identity = scope[IDENTITY_SCOPE_KEY]
    try:
        catalog = server.catalog_for_identity(identity)
    except PermissionError:
        await _send_json(send, 403, {"error": "forbidden"})
        return
    await _send_json(send, 200, catalog)


async def execute_endpoint(scope: Scope, body: bytes, send: Send) -> None:
    from .. import server

    try:
        content_type = (_header(scope, b"content-type") or "").split(";")[0].strip().lower()
    except ValueError:
        content_type = ""
    if content_type != "application/json":
        await _send_json(send, 415, {"error": "unsupported media type"})
        return
    parsed = parse_execute_body(body)
    if parsed is None:
        await _send_json(send, 400, {"error": "bad request"})
        return
    tool, arguments = parsed
    identity: Identity = scope[IDENTITY_SCOPE_KEY]
    ok, text = await server.run_tool(
        identity, tool, arguments, correlation=scope.get(CORRELATION_SCOPE_KEY)
    )
    await _send_json(send, 200, {"ok": ok, "text": text})


ENDPOINTS: dict[str, Endpoint] = {CATALOG_PATH: catalog_endpoint, EXECUTE_PATH: execute_endpoint}


# ---- top level -----------------------------------------------------------


def _client_ip(scope: Scope) -> str | None:
    """The caller's address as Cloudflare saw it (behind cloudflared the peer is loopback)."""
    try:
        raw = _header(scope, b"cf-connecting-ip")
        return str(ipaddress.ip_address(raw)) if raw else None
    except ValueError:
        return None


def _audit_request(scope: Scope, status: int) -> None:
    """One audit line per refused request and per catalog read.

    HIPAA 164.308(a)(5)(ii)(C) log-in monitoring and SOC 2 CC7.2 need failed
    authentication in the tamper-evident log, not only in the service log. Tool
    calls on /v1/execute are already audited by server.run_tool, and /healthz is
    not an access event. The response has already been sent, so a failed audit
    write cannot change it; it is logged at CRITICAL and audit.health() goes bad.
    """
    path = scope.get("path", "")
    if path == HEALTH_PATH and status < 400:
        return
    if path == EXECUTE_PATH and status == 200:
        return
    notes = scope.get(AUDIT_SCOPE_KEY, {})
    ok = status < 400
    fields: dict[str, Any] = {
        "side": "in",
        "event": "catalog" if path == CATALOG_PATH and ok else "http",
        "status": "ok" if ok else "denied",
        "http": status,
        "method": scope.get("method", "")[:16],
        "path": path if path in ROUTES or path == HEALTH_PATH else "other",
        "deny": None if ok else notes.get("deny", f"http {status}"),
        "user": notes.get("user"),
        "svc": notes.get("svc"),
        "jti": notes.get("jti"),
        "client": _client_ip(scope),
    }
    try:
        from .. import audit

        audit.audit_event(**{k: v for k, v in fields.items() if v is not None})
    except Exception as exc:  # noqa: BLE001 - never mask the response already sent
        log.critical("audit write failed for a %s response: %s", status, type(exc).__name__)


class GuardApp:
    """Top-level ASGI app: lifespan, /healthz, and the guarded /v1 routes."""

    def __init__(
        self,
        guarded: Callable[[Endpoint], ASGIApp],
        lifespan_app: ASGIApp,
        settings: HttpSettings,
    ) -> None:
        self.routes = {path: guarded(endpoint) for path, endpoint in ENDPOINTS.items()}
        self.lifespan_app = lifespan_app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind == "lifespan":
            await self.lifespan_app(scope, receive, send)
            return
        if kind != "http":
            if kind == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        headers = scope.get("headers", ())
        if (
            len(headers) > MAX_HEADER_COUNT
            or sum(len(k) + len(v) for k, v in headers) > MAX_HEADER_BYTES
        ):
            # h11's incomplete-event cap only bounds a head that arrives in
            # pieces; one that arrives in a single read is parsed whole. Enforce
            # the head budget on what was actually parsed.
            await _send_json(send, 431, {"error": "request header fields too large"})
            return

        started = False
        status = 0

        async def tracking_send(message: Message) -> None:
            nonlocal started, status
            if message["type"] == "http.response.start":
                started = True
                status = int(message["status"])
            await send(message)

        try:
            await self._dispatch(scope, receive, tracking_send)
        except Exception as exc:
            log.error("request failed: %s", type(exc).__name__)
            if not started:
                await _send_json(send, 500, {"error": "internal error"})
                status = 500
        finally:
            _audit_request(scope, status)

    async def _dispatch(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        method = scope.get("method", "")
        raw_path = scope.get("raw_path")
        if raw_path is not None and raw_path != path.encode("utf-8", "surrogateescape"):
            # The server percent-decodes the target into ``path``. Only the
            # canonical spelling routes, so the path the Worker signed is exactly
            # the bytes on the wire (no /v1%2Fexecute, no %65 tricks).
            await _send_json(send, 404, {"error": "not found"})
            return
        if path == HEALTH_PATH and method in ("GET", "HEAD") and not scope.get("query_string"):
            from .. import audit

            # Every tool call fails closed when the audit log cannot be written, so a
            # broken sink is an outage: report it to monitoring (SOC 2 CC7.3), no detail.
            if not audit.health().get("ok", True):
                await _send_body(send, 503, b"unavailable", b"text/plain; charset=utf-8")
                return
            await _send_body(send, 200, b"ok", b"text/plain; charset=utf-8")
            return
        app = self.routes.get(path)
        if app is None or scope.get("query_string"):
            await _send_json(send, 404, {"error": "not found"})
            return
        if method != ROUTES[path]:
            await _send_json(
                send, 405, {"error": "method not allowed"}, [(b"allow", ROUTES[path].encode())]
            )
            return
        try:
            with anyio.fail_after(self.settings.request_timeout):
                await app(scope, receive, send)
        except TimeoutError:
            log.warning("request timed out after %ss", self.settings.request_timeout)
            raise


def create_app(
    settings: HttpSettings | None = None,
    *,
    access_verifier: AccessVerifier | None = None,
    assertion_verifier: IdentityAssertionVerifier | None = None,
    enrollment_check: EnrollmentCheck | None = None,
) -> ASGIApp:
    """Build the broker ASGI app. Raises ConfigError / AccessConfigError /
    AssertionConfigError on missing or bad configuration (fail closed)."""
    from .. import server  # late import: server imports this package

    settings = settings or HttpSettings.from_env()
    if settings.require_access_jwt:
        access_verifier = access_verifier or AccessVerifier.for_broker_from_env()
        if access_verifier.service_client_ids is None:
            raise ConfigError("the broker Access verifier must pin the Worker's service token")
    else:
        access_verifier = None
        log.warning(
            "BROKER_REQUIRE_ACCESS_JWT=0: Access service-token check disabled "
            "(Workers VPC mode); identity assertions and loopback bind still apply"
        )
    assertion_verifier = assertion_verifier or IdentityAssertionVerifier.from_credentials()
    request_limiter = RateLimiter.from_env(scale=5)

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with server.client_lifespan():
            if access_verifier is not None:
                await access_verifier.prefetch()
            try:
                yield
            finally:
                if access_verifier is not None:
                    await access_verifier.aclose()

    def guarded(endpoint: Endpoint) -> ASGIApp:
        return RequestSizeCap(
            HostCheck(
                BrokerAuth(
                    endpoint,
                    assertion_verifier=assertion_verifier,
                    access_verifier=access_verifier,
                    enrollment_check=enrollment_check or _default_enrollment_check,
                    request_limiter=request_limiter,
                    body_timeout=settings.body_timeout,
                ),
                settings.allowed_hosts,
            ),
            settings.max_request_bytes,
        )

    return SecurityHeaders(GuardApp(guarded, Starlette(lifespan=lifespan), settings))


def header_timeout_protocol(header_timeout: float) -> type:
    """uvicorn's h11 protocol plus a deadline for receiving request headers.

    Stock uvicorn arms no timer until the first response is sent: a connection
    that sends nothing, or a partial request line/header block, is held forever
    and counts against ``limit_concurrency``, so a few dozen slowloris sockets
    make every real request 503. Here a timer runs whenever the connection is
    waiting for the head of a request (h11 ``their_state`` IDLE); when it fires
    and the head is still incomplete, the transport is closed. Body slowness is
    bounded separately by ``body_timeout`` in BrokerAuth.
    """
    import h11
    from uvicorn.protocols.http.h11_impl import H11Protocol

    class HeaderTimeoutH11Protocol(H11Protocol):
        _header_timer: Any = None

        def connection_made(self, transport: Any) -> None:  # type: ignore[override]
            super().connection_made(transport)
            self._arm_header_timer()

        def data_received(self, data: bytes) -> None:
            super().data_received(data)
            if self.conn.their_state is h11.IDLE:
                self._arm_header_timer()
            else:
                self._disarm_header_timer()

        def connection_lost(self, exc: Exception | None) -> None:
            self._disarm_header_timer()
            super().connection_lost(exc)

        def _arm_header_timer(self) -> None:
            if self._header_timer is None:
                self._header_timer = self.loop.call_later(header_timeout, self._header_expired)

        def _disarm_header_timer(self) -> None:
            if self._header_timer is not None:
                self._header_timer.cancel()
                self._header_timer = None

        def _header_expired(self) -> None:
            self._header_timer = None
            if self.conn.their_state is h11.IDLE and not self.transport.is_closing():
                log.info("closing connection: request head not received in %ss", header_timeout)
                self.transport.close()

    return HeaderTimeoutH11Protocol


def uvicorn_options(settings: HttpSettings) -> dict[str, Any]:
    """Keyword arguments for uvicorn.run / uvicorn.Config (one place, tested)."""
    return {
        "host": settings.bind,
        "port": settings.port,
        # Never trust X-Forwarded-*: identity comes from signed tokens, not addresses.
        "proxy_headers": False,
        "forwarded_allow_ips": "",
        "server_header": False,
        "date_header": False,
        "access_log": False,
        # Pure-Python h11 (strict framing: refuses Content-Length together with
        # Transfer-Encoding and malformed lengths), never "auto": an installed
        # httptools would silently replace it and drop the header-size cap below.
        "http": header_timeout_protocol(settings.header_timeout),
        "ws": "none",
        "lifespan": "on",
        "limit_concurrency": settings.max_concurrency,
        "backlog": 128,
        "timeout_keep_alive": 5,
        "timeout_graceful_shutdown": 10,
        # Whole request head (request line + headers) at most 32 KiB -> 431/400.
        "h11_max_incomplete_event_size": 32 * 1024,
        "log_level": "info",
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    # httpx logs every outbound URL at info; the SDK can log content at debug.
    for noisy in ("mcp", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    import uvicorn

    from .. import server

    try:
        server._validate_config("broker")
        settings = HttpSettings.from_env()
        check_bind(settings.bind)
        application = create_app(settings)
    except (ConfigError, AccessConfigError, AssertionConfigError, RuntimeError, ValueError) as exc:
        print(f"proxmox-mcp-http: refusing to start: {exc}", file=sys.stderr)
        sys.exit(2)

    log.info(
        "broker listening on %s:%d (access jwt %s, %d allowed host(s))",
        settings.bind,
        settings.port,
        "required" if settings.require_access_jwt else "OFF",
        len(settings.allowed_hosts),
    )
    uvicorn.run(application, **uvicorn_options(settings))
