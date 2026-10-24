"""Caller identity for one MCP request.

Shared contract between the transport layer (which authenticates the caller from
the Cloudflare Access JWT) and the policy/audit layers (which decide and record
what that caller may do). The transport sets ``current_identity`` for the
duration of a request; everything downstream reads it.

On stdio transport there is no network caller. The stdio entry point sets a
``local`` identity so policy still applies and audit lines still carry an actor.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Identity:
    # Stable subject: the Access user email, or the service-token client id.
    subject: str
    # "user" (Access identity), "service" (Access service token), "local" (stdio).
    kind: str
    # Access JWT claims we keep for audit (never the token itself).
    email: str | None = None
    groups: tuple[str, ...] = field(default_factory=tuple)
    country: str | None = None
    # Cloudflare request id (Cf-Ray) when present, to correlate with Access logs.
    ray_id: str | None = None


current_identity: ContextVar[Identity | None] = ContextVar("current_identity", default=None)


def require_identity() -> Identity:
    """The caller of the current request. Fails closed when no layer set one."""
    ident = current_identity.get()
    if ident is None:
        raise PermissionError("No authenticated caller for this request")
    return ident
