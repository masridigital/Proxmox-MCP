"""X-MCP-Identity: the Worker's per-request statement of who the user is.

The Cloudflare Worker authenticates the person (Access, Entra) and then, for each
broker call, signs a short-lived compact JWS with its Ed25519 private key. The
broker holds only the public key (credential ``worker-identity.pub``, PEM), so
compromising the broker does not let anyone mint identities.

Header  {"alg": "EdDSA", "typ": "JWT"}           EdDSA over Ed25519 only
Claims  iss    "proxmox-mcp-worker"
        aud    "proxmox-broker"
        sub    user email, lowercase
        iat    issue time; exp - iat <= 60 s; 30 s leeway for clock skew
        exp
        jti    unique id; replay cache 120 s
        req    sha256 hex of the exact HTTP request body bytes
        method HTTP method of this broker call
        path   path of this broker call
        ray    Cf-Ray of the user's request (optional, for log correlation)

Binding ``req``/``method``/``path`` means a captured assertion cannot be attached
to a different body or endpoint, and ``jti`` means it cannot be replayed. The
replay window (120 s) covers the longest life a token can have: iat may be up to
30 s ahead, exp at most 60 s after iat, plus 30 s leeway.

Pure Python and portable (Linux dev, Windows Server broker).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from ..identity import Identity

HEADER = "x-mcp-identity"
ISSUER = "proxmox-mcp-worker"
AUDIENCE = "proxmox-broker"
PUBLIC_KEY_CREDENTIAL = "worker-identity.pub"

LEEWAY_SECONDS = 30
MAX_LIFETIME_SECONDS = 60
REPLAY_WINDOW_SECONDS = 120.0
MAX_REPLAY_ENTRIES = 100_000
MAX_TOKEN_BYTES = 4096

_EMAIL_RE = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$")
_JTI_RE = re.compile(r"^[A-Za-z0-9-]{8,128}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_RAY_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


class AssertionConfigError(RuntimeError):
    """The Worker public key is missing or unusable; refuse to start."""


class AssertionDenied(Exception):
    """The identity assertion is missing or invalid. ``reason`` is for the log only."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class VerifiedAssertion:
    identity: Identity
    jti: str


def load_public_key(pem: str | bytes) -> Ed25519PublicKey:
    data = pem.encode() if isinstance(pem, str) else pem
    try:
        key = load_pem_public_key(data)
    except (ValueError, TypeError):
        raise AssertionConfigError(f"{PUBLIC_KEY_CREDENTIAL} is not a PEM public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise AssertionConfigError(f"{PUBLIC_KEY_CREDENTIAL} must be an Ed25519 public key")
    return key


def load_public_key_from_credentials() -> Ed25519PublicKey:
    from ..credentials import read_credential

    try:
        pem = read_credential(PUBLIC_KEY_CREDENTIAL)
    except Exception as exc:
        raise AssertionConfigError(
            f"cannot read credential {PUBLIC_KEY_CREDENTIAL}: {type(exc).__name__}"
        ) from None
    return load_public_key(pem)


class ReplayCache:
    """Seen jti values, each remembered for the replay window. Bounded, thread safe.

    When full of live entries a new jti is refused (fail closed) instead of
    forgetting one that could then be replayed.
    """

    def __init__(
        self,
        window: float = REPLAY_WINDOW_SECONDS,
        max_entries: int = MAX_REPLAY_ENTRIES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.window = window
        self.max_entries = max_entries
        self._clock = clock
        self._seen: OrderedDict[str, float] = OrderedDict()  # jti -> expiry, insertion order
        self._lock = threading.Lock()

    def add(self, jti: str) -> None:
        """Record ``jti``; raise AssertionDenied if it was seen inside the window."""
        now = self._clock()
        with self._lock:
            while self._seen:
                oldest, expiry = next(iter(self._seen.items()))
                if expiry > now:
                    break
                del self._seen[oldest]
            if jti in self._seen:
                raise AssertionDenied("replayed jti")
            if len(self._seen) >= self.max_entries:
                raise AssertionDenied("replay cache full")
            self._seen[jti] = now + self.window

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


class IdentityAssertionVerifier:
    def __init__(
        self,
        public_key: Ed25519PublicKey,
        *,
        replay_cache: ReplayCache | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(public_key, Ed25519PublicKey):
            raise AssertionConfigError("identity assertion key must be Ed25519")
        self._key = public_key
        self._replay = replay_cache or ReplayCache()
        self._now = now

    @classmethod
    def from_credentials(cls) -> IdentityAssertionVerifier:
        return cls(load_public_key_from_credentials())

    def verify(
        self, token: str | None, *, body: bytes, method: str, path: str
    ) -> VerifiedAssertion:
        if not token:
            raise AssertionDenied("missing assertion")
        if len(token) > MAX_TOKEN_BYTES or token.count(".") != 2:
            raise AssertionDenied("malformed assertion")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise AssertionDenied("malformed assertion header") from None
        # The algorithm is fixed by configuration; the token's header only has to agree.
        if header.get("alg") != "EdDSA":
            raise AssertionDenied("algorithm not allowed")
        if any(k in header for k in ("crit", "jku", "jwk", "x5u", "x5c")):
            raise AssertionDenied("unsupported assertion header")

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=self._key,
                algorithms=["EdDSA"],
                audience=AUDIENCE,
                issuer=ISSUER,
                leeway=LEEWAY_SECONDS,
                options={
                    "require": ["iss", "aud", "sub", "iat", "exp", "jti"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_nbf": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.PyJWTError as exc:
            raise AssertionDenied(f"invalid assertion: {type(exc).__name__}") from None

        iat, exp = claims["iat"], claims["exp"]
        if not all(isinstance(v, int | float) and not isinstance(v, bool) for v in (iat, exp)):
            raise AssertionDenied("bad time claims")
        if not 0 < exp - iat <= MAX_LIFETIME_SECONDS:
            raise AssertionDenied("assertion lifetime too long")
        if iat > self._now() + LEEWAY_SECONDS:
            raise AssertionDenied("assertion issued in the future")

        # PyJWT accepts aud as a list containing ours; require exactly ours.
        if claims.get("aud") != AUDIENCE:
            raise AssertionDenied("audience mismatch")

        sub = claims.get("sub")
        if not isinstance(sub, str) or len(sub) > 254 or not _EMAIL_RE.match(sub):
            raise AssertionDenied("sub is not a lowercase email")

        req = claims.get("req")
        if not isinstance(req, str) or not _HEX64_RE.match(req):
            raise AssertionDenied("missing body hash")
        if not hmac.compare_digest(req, hashlib.sha256(body).hexdigest()):
            raise AssertionDenied("body hash mismatch")
        if claims.get("method") != method:
            raise AssertionDenied("method mismatch")
        if claims.get("path") != path:
            raise AssertionDenied("path mismatch")

        jti = claims.get("jti")
        if not isinstance(jti, str) or not _JTI_RE.match(jti):
            raise AssertionDenied("bad jti")
        ray = claims.get("ray")
        ray_id = ray if isinstance(ray, str) and _RAY_RE.match(ray) else None

        # Last: only a fully valid assertion consumes its jti.
        self._replay.add(jti)
        return VerifiedAssertion(
            identity=Identity(subject=sub, kind="user", email=sub, ray_id=ray_id), jti=jti
        )
