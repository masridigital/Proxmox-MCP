#!/usr/bin/env python3
"""Proxmox VE MCP server: tool exposure, per-call policy, audit and dispatch.

Transport-independent core. Two entry points share it:
  * ``proxmox-mcp-server``  stdio MCP, for local development. The caller is the
    synthetic ``local`` identity (its mode comes from MCP_LOCAL_MODE, default ro).
  * ``proxmox-mcp-http``    the on-prem broker (proxmox_mcp.transport.http_app):
    /v1/catalog and /v1/execute for the Cloudflare Worker, which speaks MCP to
    Claude. The broker authenticates every request and calls ``run_tool`` /
    ``catalog_for_identity`` here with the asserted user's Identity.

Every tool call runs as exactly one identity, rate limited per subject.
Real tools go through ``_execute``: inbound tool policy, audit line in, dispatch
to the tool module with the shared Proxmox client (whose outbound policy and
per-user token apply), audit line out, output rendering (redaction, size cap,
untrusted-data label). Errors are tool results with ``isError: true`` carrying a
short, safe message; tracebacks and exception reprs never leave the process.

Configuration (environment):
    MCP_TOOL_MODE      dynamic (default; 3 meta-tools, MCP-STD-02) | static
    MCP_RATE_PER_MIN   tools/call per subject per minute (default 60)
    MCP_RATE_PER_DAY   tools/call per subject per day (default 2000)
    Proxmox connection, TLS, enrollment, audit and output settings: see client.py,
    enrollment.py, audit.py, output.py.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import sys
import time
from collections.abc import AsyncIterator
from contextvars import ContextVar
from typing import Any

import httpx
import mcp.server.stdio
from mcp.server import Server
from mcp.types import CallToolResult, TextContent, Tool, ToolAnnotations

from . import audit, config, output, policy, router
from .client import ProxmoxClient
from .enrollment import enrollment_for
from .identity import Identity, current_identity, require_identity
from .transport import IDENTITY_SCOPE_KEY
from .transport.ratelimit import RateLimited, RateLimiter

log = logging.getLogger(__name__)

LOCAL_IDENTITY = Identity(subject="local", kind="local")
META_TOOL_NAMES = frozenset({"list_tools", "describe_tool_input", "execute_tool"})
TOOL_MODES = ("dynamic", "static")

app = Server("proxmox-mcp-server")

# One Proxmox client per process. Created by client_lifespan() (stdio main, or the
# HTTP app's lifespan) and closed there, in the event loop that used it.
proxmox: ProxmoxClient | None = None
limiter = RateLimiter.from_env()

# Extra correlation fields (assertion jti, calling service) merged into every audit
# line of the current request. Set by the broker; empty on stdio.
audit_context: ContextVar[dict[str, Any] | None] = ContextVar("audit_context", default=None)


# ---- configuration -------------------------------------------------------


def tool_mode() -> str:
    mode = os.getenv("MCP_TOOL_MODE", "dynamic").strip().lower() or "dynamic"
    if mode not in TOOL_MODES:
        # Unreachable after _validate_config(); never guess a mode at call time.
        raise RuntimeError("MCP_TOOL_MODE must be 'dynamic' or 'static'")
    return mode


def _validate_config(role: str = "stdio") -> None:
    """Refuse to start on configuration this module cannot honour (fail closed).

    config.init applies the strict, typo-proof settings check for the role
    (broker or stdio) and logs every dangerous flag; ConfigError is a RuntimeError.
    """
    if role == "stdio":
        # Developer convenience only; the broker never reads a .env file.
        from dotenv import load_dotenv

        load_dotenv()
    config.init(role)
    tool_mode()
    RateLimiter.from_env()  # raises on malformed MCP_RATE_* values
    if not router.REGISTRY:
        raise RuntimeError("tool registry is empty")


def _client() -> ProxmoxClient:
    global proxmox
    if proxmox is None:
        proxmox = ProxmoxClient()
    return proxmox


@contextlib.asynccontextmanager
async def client_lifespan() -> AsyncIterator[ProxmoxClient]:
    """Own the process-wide Proxmox client for the lifetime of a transport."""
    global proxmox
    # Write the start event (version + catalog hash) before serving; fails closed if the
    # audit log cannot be written.
    audit.start()
    client = _client()
    try:
        yield client
    finally:
        proxmox = None
        await client.close()


# ---- identity ------------------------------------------------------------


def _request_scope() -> dict[str, Any] | None:
    """ASGI scope of the HTTP request behind the current MCP message, if any."""
    try:
        request = app.request_context.request
    except LookupError:
        return None
    scope = getattr(request, "scope", None)
    return scope if isinstance(scope, dict) else None


def _resolve_identity() -> Identity:
    """The caller of this message.

    Over HTTP the guard put the verified Identity into the request scope; that is
    authoritative, and a request that reached here without one is refused even if
    some identity happens to be set in the task context. On stdio there is no
    request and the identity comes from the context (the local identity).
    """
    scope = _request_scope()
    if scope is not None:
        ident = scope.get(IDENTITY_SCOPE_KEY)
        if not isinstance(ident, Identity):
            raise PermissionError("No authenticated caller for this request")
        return ident
    return require_identity()


# ---- helpers -------------------------------------------------------------


def _args_digest(args: dict[str, Any]) -> tuple[list[str], str]:
    """Argument keys and a sha256 of the canonical arguments; never the values."""
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return sorted(str(k) for k in args), hashlib.sha256(canonical.encode()).hexdigest()


def _audit(ident: Identity, **fields: Any) -> None:
    try:
        extra = audit_context.get() or {}
        audit.audit_event(user=ident.subject, kind=ident.kind, ray=ident.ray_id, **extra, **fields)
    except Exception as exc:  # audit trouble must be visible but must not leak details
        log.error("audit_event failed: %s", type(exc).__name__)
        raise


def _error_result(message: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=output.render_error(message))], isError=True
    )


def _safe_message(exc: BaseException) -> str:
    """What the caller may see about a failure. Only our own, known-safe texts pass."""
    if isinstance(exc, policy.PolicyDenied):
        return f"blocked by policy: {exc.reason}"
    if isinstance(exc, RateLimited):
        return exc.reason
    if isinstance(exc, PermissionError):
        # enrollment ("not enrolled") and outbound policy ("blocked by outbound policy: ...")
        return str(exc) or "permission denied"
    if isinstance(exc, httpx.HTTPStatusError):
        # Built by the client from the Proxmox status line and error body; redacted
        # again by output.render_error.
        return str(exc)
    if isinstance(exc, httpx.HTTPError):
        return "Proxmox API request failed"
    if isinstance(exc, KeyError):
        return f"missing required argument: {exc.args[0]!s}" if exc.args else "missing argument"
    if isinstance(exc, ValueError | TypeError):
        # Unknown tool / invalid input from the router or a tool module.
        return str(exc) or "invalid input"
    return "internal error"


def _as_tool(tool_def: dict[str, Any]) -> Tool:
    name = tool_def["name"]
    tier = policy.tool_tier(name)
    return Tool(
        name=name,
        description=tool_def.get("description", ""),
        inputSchema=tool_def["inputSchema"],
        annotations=ToolAnnotations(
            readOnlyHint=tier == "read",
            destructiveHint=tier == "admin",
            openWorldHint=False,
        ),
    )


def _to_content(result: Any) -> CallToolResult:
    if isinstance(result, CallToolResult):
        return result
    if isinstance(result, str):
        return CallToolResult(content=[TextContent(type="text", text=result)], isError=False)
    if isinstance(result, list) and all(isinstance(c, TextContent) for c in result):
        return CallToolResult(content=result, isError=False)
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(result, default=str))], isError=False
    )


# ---- execution -----------------------------------------------------------


async def _execute(tool: str, args: dict[str, Any]) -> str:
    """Run one real Proxmox tool as the current caller and return rendered text.

    Raises on denial or failure; call_tool turns that into an isError result.
    """
    ident = require_identity()
    if not isinstance(args, dict):
        raise ValueError(f"Invalid input for tool {tool}: arguments must be an object")
    rpc_tool = "execute_tool" if tool_mode() == "dynamic" or audit_context.get() else tool
    arg_keys, arg_hash = _args_digest(args)
    base = {
        "rpc": "tools/call",
        "tool": rpc_tool,
        "target": tool,
        "arg_keys": arg_keys,
        "args_sha256": arg_hash,
    }

    try:
        policy.check_tool(ident, tool)
    except (policy.PolicyDenied, PermissionError) as exc:
        reason = exc.reason if isinstance(exc, policy.PolicyDenied) else str(exc)
        _audit(ident, side="in", status="denied", deny=reason, **base)
        raise

    entry = router.REGISTRY.get(tool)
    if entry is None:  # policy classifies unknown tools as forbidden; belt and braces
        _audit(ident, side="in", status="denied", deny="unknown tool", **base)
        raise ValueError(f"Unknown tool: {tool}")
    _, module = entry
    # Schema check after the policy check, so a denied caller learns nothing about
    # the schema; the broker re-validates whatever the Worker already checked.
    try:
        router.validate_arguments(tool, args)
    except ValueError:
        _audit(ident, side="in", status="denied", deny="invalid input", **base)
        raise

    _audit(ident, side="in", status="allowed", **base)
    started = time.monotonic()
    try:
        result = await module.handle(tool, args, _client())
        text = output.render_result(result)
    except Exception as exc:
        _audit(
            ident,
            side="out",
            status="error",
            error=type(exc).__name__,
            ms=round((time.monotonic() - started) * 1000),
            **base,
        )
        raise
    _audit(
        ident,
        side="out",
        status="ok",
        bytes=len(text.encode()),
        ms=round((time.monotonic() - started) * 1000),
        **base,
    )
    return text


async def run_tool(
    identity: Identity,
    tool: str,
    arguments: Any,
    *,
    correlation: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    """One real tool call for the broker: (ok, rendered text). Never raises.

    Same pipeline as an MCP execute_tool: rate limit, policy, schema, audit,
    handler, output rendering. Denials and failures come back as (False, text).
    """
    ident_token = current_identity.set(identity)
    ctx_token = audit_context.set(dict(correlation or {}))
    # Correlation (jti, svc) also reaches the client's outbound lines, so an auditor can
    # join the Worker event, the broker decision and every Proxmox call it caused.
    bound = audit.bind(**{k: v for k, v in (correlation or {}).items() if k in ("jti", "svc")})
    bound.__enter__()
    try:
        if not isinstance(arguments, dict):
            _audit(
                identity,
                side="in",
                rpc="execute",
                tool="execute_tool",
                target=tool,
                status="denied",
                deny="invalid input",
            )
            return False, output.render_error(
                f"Invalid input for tool {tool}: arguments must be an object"
            )
        try:
            limiter.hit(identity.subject)
        except RateLimited:
            _audit(
                identity,
                side="in",
                rpc="execute",
                tool="execute_tool",
                target=tool,
                status="denied",
                deny="rate limit",
            )
            raise
        return True, await _execute(tool, arguments)
    except Exception as exc:
        message = _safe_message(exc)
        if message == "internal error":
            log.error("execute %s failed: %s", tool, type(exc).__name__)
            log.debug("execute failure detail", exc_info=True)
        return False, output.render_error(message)
    finally:
        bound.__exit__(None, None, None)
        audit_context.reset(ctx_token)
        current_identity.reset(ident_token)


def catalog_for_identity(identity: Identity) -> dict[str, Any]:
    """The tools this caller may run. Raises PermissionError when not enrolled."""
    enrollment = enrollment_for(identity)
    return {
        "mode": enrollment.mode,
        "version": policy.catalog_version(enrollment.mode),
        "tools": policy.catalog_for(enrollment.mode),
    }


@app.list_tools()
async def list_tools() -> list[Tool]:
    try:
        ident = _resolve_identity()
        if tool_mode() == "dynamic":
            return list(router.meta_tools())
        token = current_identity.set(ident)
        try:
            return [_as_tool(d) for d in router.visible_tools(ident)]
        finally:
            current_identity.reset(token)
    except Exception as exc:
        # Fail closed with an empty catalog; the reason goes to the log only.
        log.warning("tools/list refused: %s", type(exc).__name__)
        return []


@app.call_tool(validate_input=False)
async def call_tool(name: str, arguments: Any) -> CallToolResult:
    # Input validation against the advertised schema happens in the router
    # (describe/execute) and in the tool modules; the SDK's cache-based check is
    # off because in static mode the cached catalog is per-caller.
    try:
        ident = _resolve_identity()
    except Exception:
        return _error_result("No authenticated caller for this request")

    token = current_identity.set(ident)
    try:
        args = arguments if isinstance(arguments, dict) else {}
        try:
            limiter.hit(ident.subject)
        except RateLimited as exc:
            _audit(
                ident, side="in", rpc="tools/call", tool=name, status="denied", deny="rate limit"
            )
            return _error_result(exc.reason)

        if tool_mode() == "dynamic":
            if name not in META_TOOL_NAMES:
                # Real tool names are not exposed at the protocol level in dynamic mode.
                _audit(
                    ident,
                    side="in",
                    rpc="tools/call",
                    tool=name,
                    status="denied",
                    deny="not exposed",
                )
                return _error_result(f"Unknown tool: {name}. Use list_tools and execute_tool.")
            if name != "execute_tool":
                _audit(ident, side="in", rpc="tools/call", tool=name, status="allowed")
            result = await router.handle_meta(name, args, execute=_execute)
            return _to_content(result)

        return _to_content(await _execute(name, args))
    except Exception as exc:
        message = _safe_message(exc)
        if message == "internal error":
            log.error("tools/call %s failed: %s", name, type(exc).__name__)
            log.debug("tools/call failure detail", exc_info=True)
        return _error_result(message)
    finally:
        current_identity.reset(token)


# ---- stdio entry point ---------------------------------------------------


async def main() -> None:
    _validate_config()
    # stdio has no network caller: everything in this process runs as `local`.
    current_identity.set(LOCAL_IDENTITY)
    print(f"Proxmox VE MCP server (stdio, {tool_mode()} mode)", file=sys.stderr)
    async with client_lifespan() as client:
        authenticate = getattr(client, "authenticate", None)
        if authenticate is not None:
            await authenticate()
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())


def run() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server stopped", file=sys.stderr)
    except Exception as exc:
        # Type only: a config error message is ours, but an arbitrary exception's
        # text could carry a secret.
        print(f"Fatal: {type(exc).__name__}: {_startup_message(exc)}", file=sys.stderr)
        sys.exit(1)


def _startup_message(exc: BaseException) -> str:
    return str(exc) if isinstance(exc, RuntimeError | ValueError) else "see log"


if __name__ == "__main__":
    run()
