"""Cloudflare Access application-token verifier.

Cloudflare Access forwards every request it lets through with the application
token in the ``Cf-Access-Jwt-Assertion`` header. This module verifies that token
in process, so the server never relies on cloudflared having done it (defense in
depth: a local process that can reach 127.0.0.1:<port> must still present a
token signed by the team's Access keys for this application).

What a Cloudflare Access application token looks like:
  header  {"alg": "RS256", "kid": "<key id>", "typ": "JWT"}
  claims  aud   ["<application AUD tag>"]   (a list)
          iss   "https://<team>.cloudflareaccess.com"   (no trailing slash)
          exp / iat / nbf, type "app", identity_nonce, sub (user uuid), country
          email                      user tokens
          common_name "<id>.access"  service tokens (email absent, sub empty)
  keys    https://<team>.cloudflareaccess.com/cdn-cgi/access/certs
          {"keys": [JWK, ...], "public_cert": ..., "public_certs": [...]},
          rotated by Cloudflare every six weeks with overlap.

Verification is strict: RS256 only (``none``/HS*/ES* refused before any key is
touched, so a public key can never be used as an HMAC secret), key chosen by
``kid`` from the team JWKS only, exact issuer, audience intersection, exp/nbf/iat
all required with at most 60 s leeway, and ``type`` must be ``app`` when present
(an org-level token from the team domain is not an application token).

Configuration is read once and a missing or malformed value raises
AccessConfigError: the HTTP entry point refuses to start (fail closed).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

import anyio
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from ..identity import Identity
from .jws_strict import MalformedJws, parse_compact

log = logging.getLogger(__name__)

JWT_HEADER = "cf-access-jwt-assertion"
EMAIL_HEADER = "cf-access-authenticated-user-email"

LEEWAY_SECONDS = 60
JWKS_TTL_SECONDS = 3600.0
# A JWKS refetch triggered by an unknown kid happens at most this often, so a
# stream of forged kids cannot turn the server into a fetch amplifier.
UNKNOWN_KID_REFETCH_SECONDS = 60.0
# After a failed fetch, wait this long before trying again.
FETCH_RETRY_SECONDS = 10.0
# Keep using the last good key set this long if Cloudflare cannot be reached.
MAX_STALE_SECONDS = 24 * 3600.0
MAX_TOKEN_BYTES = 8192
MAX_JWKS_BYTES = 64 * 1024
MIN_RSA_BITS = 2048

_AUD_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HOST_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_KID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_EMAIL_RE = re.compile(r"^[^\s@\x00-\x1f\x7f]{1,64}@[^\s@\x00-\x1f\x7f]{1,255}$")
_COMMON_NAME_RE = re.compile(r"^[A-Za-z0-9._@-]{1,255}$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_TRUE = {"1", "true", "yes"}
# Cloudflare Access application tokens carry exactly these header parameters.
_HEADER_PARAMS = frozenset({"alg", "kid", "typ"})


class AccessConfigError(RuntimeError):
    """Access verification is not configured correctly; refuse to start."""


class AccessDenied(Exception):
    """The request does not carry an acceptable Access token.

    ``reason`` is for the server log only; callers get a bare 401.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class AccessUnavailable(Exception):
    """The signing keys cannot be obtained; answer 503, never fall open."""


def normalize_team_domain(value: str) -> str:
    """``https://<team>.cloudflareaccess.com`` with no trailing slash, or raise.

    The value is the issuer the tokens must carry and the origin of the JWKS
    URL, so it must be an https origin and nothing else: no path, query,
    fragment, credentials or port.
    """
    raw = (value or "").strip()
    if not raw:
        raise AccessConfigError("CF_ACCESS_TEAM_DOMAIN is not set")
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or not _HOST_RE.fullmatch(host)
        or parts.username is not None
        or parts.password is not None
        or parts.port is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise AccessConfigError(
            "CF_ACCESS_TEAM_DOMAIN must be an https origin such as https://<team>.cloudflareaccess.com"
        )
    return f"https://{host}"


def parse_audiences(value: str | Iterable[str]) -> tuple[str, ...]:
    items = value.split(",") if isinstance(value, str) else list(value)
    auds = tuple(a.strip() for a in items if a and a.strip())
    if not auds:
        raise AccessConfigError("CF_ACCESS_AUD is not set")
    for aud in auds:
        if not _AUD_RE.fullmatch(aud):
            raise AccessConfigError("CF_ACCESS_AUD contains an invalid value")
    return auds


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in _TRUE


class AccessVerifier:
    def __init__(
        self,
        team_domain: str,
        audiences: str | Iterable[str],
        *,
        allow_service_tokens: bool = False,
        service_client_ids: Iterable[str] | None = None,
        http_client: httpx.AsyncClient | None = None,
        jwks_ttl: float = JWKS_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.issuer = normalize_team_domain(team_domain)
        self.audiences = parse_audiences(audiences)
        self.allow_service_tokens = allow_service_tokens
        # When set, ONLY service tokens whose common_name (the service token's
        # client id) is listed are accepted, and user tokens are refused. This is
        # the broker mode: the caller is the Worker, never a person.
        self.service_client_ids: frozenset[str] | None = None
        if service_client_ids is not None:
            ids = frozenset(c.strip() for c in service_client_ids if c and c.strip())
            if not ids or not all(_COMMON_NAME_RE.fullmatch(c) for c in ids):
                raise AccessConfigError("BROKER_ALLOWED_SERVICE_CLIENT_IDS is not set or invalid")
            self.service_client_ids = ids
            self.allow_service_tokens = True
        self.certs_url = f"{self.issuer}/cdn-cgi/access/certs"
        self.jwks_ttl = jwks_ttl
        self._clock = clock
        self._client = http_client
        self._owns_client = http_client is None
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._last_unknown_kid_fetch = -float("inf")
        self._last_failure = -float("inf")
        self._lock: anyio.Lock | None = None

    @classmethod
    def from_env(cls) -> AccessVerifier:
        return cls(
            os.getenv("CF_ACCESS_TEAM_DOMAIN", ""),
            os.getenv("CF_ACCESS_AUD", ""),
            allow_service_tokens=_env_flag("MCP_ALLOW_SERVICE_TOKENS"),
        )

    @classmethod
    def for_broker_from_env(cls) -> AccessVerifier:
        """Broker mode: the broker's Access app AUD and the Worker's service token id(s)."""
        return cls(
            os.getenv("CF_ACCESS_TEAM_DOMAIN", ""),
            os.getenv("CF_ACCESS_AUD", ""),
            service_client_ids=os.getenv("BROKER_ALLOWED_SERVICE_CLIENT_IDS", "").split(","),
        )

    # ---- key set -------------------------------------------------------

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            # TLS verification on (httpx default), no redirects: the keys must come
            # from the team domain itself.
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(5.0), follow_redirects=False, verify=True
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    async def _download(self) -> dict[str, Any]:
        async with self._http().stream(
            "GET", self.certs_url, headers={"Accept": "application/json"}
        ) as resp:
            if resp.status_code != 200:
                raise AccessUnavailable(f"JWKS fetch returned HTTP {resp.status_code}")
            body = bytearray()
            async for chunk in resp.aiter_bytes():
                body.extend(chunk)
                if len(body) > MAX_JWKS_BYTES:
                    raise AccessUnavailable("JWKS response too large")
        doc = json.loads(bytes(body))
        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            raise AccessUnavailable("JWKS document has no keys")
        return doc

    @staticmethod
    def _parse_keys(doc: dict[str, Any]) -> dict[str, Any]:
        keys: dict[str, Any] = {}
        for jwk in doc["keys"]:
            if not isinstance(jwk, dict):
                continue
            kid = jwk.get("kid")
            if (
                jwk.get("kty") != "RSA"
                or not isinstance(kid, str)
                or not _KID_RE.fullmatch(kid)
                or jwk.get("alg", "RS256") != "RS256"
                or jwk.get("use", "sig") != "sig"
            ):
                continue
            try:
                key = RSAAlgorithm.from_jwk(jwk)
            except (jwt.PyJWTError, ValueError, TypeError, KeyError):
                continue
            # A JWK carrying private parameters would still verify; only ever keep
            # the public half, and refuse weak moduli.
            public = key.public_key() if hasattr(key, "public_key") else key
            if getattr(public, "key_size", 0) < MIN_RSA_BITS:
                continue
            keys[kid] = public
        if not keys:
            raise AccessUnavailable("JWKS document has no usable RS256 keys")
        return keys

    async def _refresh(self, *, reason: str) -> None:
        if self._lock is None:
            self._lock = anyio.Lock()
        before = self._fetched_at
        async with self._lock:
            if self._fetched_at != before:
                return  # another task refreshed while we waited
            now = self._clock()
            if now - self._last_failure < FETCH_RETRY_SECONDS:
                return
            try:
                keys = self._parse_keys(await self._download())
            except (AccessUnavailable, httpx.HTTPError, ValueError) as exc:
                self._last_failure = now
                log.warning(
                    "Access JWKS refresh (%s) failed: %s",
                    reason,
                    exc if isinstance(exc, AccessUnavailable) else type(exc).__name__,
                )
                return
            self._keys = keys
            self._fetched_at = now
            log.info("Access JWKS refreshed (%s): %d key(s)", reason, len(keys))

    def _usable(self) -> bool:
        return (
            self._fetched_at is not None
            and self._clock() - self._fetched_at <= MAX_STALE_SECONDS
            and bool(self._keys)
        )

    async def prefetch(self) -> None:
        """Warm the key cache at start-up. Failure is logged, not fatal."""
        await self._refresh(reason="startup")

    async def _key_for(self, kid: str) -> Any:
        now = self._clock()
        if self._fetched_at is None or now - self._fetched_at > self.jwks_ttl:
            await self._refresh(reason="ttl")
        if not self._usable():
            raise AccessUnavailable("no Access signing keys available")
        key = self._keys.get(kid)
        if key is None and now - self._last_unknown_kid_fetch >= UNKNOWN_KID_REFETCH_SECONDS:
            self._last_unknown_kid_fetch = now
            await self._refresh(reason="unknown kid")
            key = self._keys.get(kid)
        if key is None:
            raise AccessDenied("unknown kid")
        return key

    # ---- tokens --------------------------------------------------------

    async def verify(self, token: str) -> dict[str, Any]:
        """Verified claims of an Access application token, or AccessDenied."""
        # Strict pre-parse: canonical base64url, unique JSON keys, header
        # allowlist {alg, kid, typ}. The algorithm comes from configuration, never
        # from the token: anything but RS256 is refused before a key is looked up.
        try:
            header, _ = parse_compact(
                token, max_bytes=MAX_TOKEN_BYTES, alg="RS256", allowed_header=_HEADER_PARAMS
            )
        except MalformedJws as exc:
            raise AccessDenied(f"malformed token: {exc}") from None
        kid = header.get("kid")
        if not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
            raise AccessDenied("missing kid")

        key = await self._key_for(kid)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=list(self.audiences),
                leeway=LEEWAY_SECONDS,
                options={
                    "require": ["exp", "iat", "nbf", "iss", "aud"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": False,  # checked below, exact match
                },
            )
        except jwt.PyJWTError as exc:
            raise AccessDenied(f"invalid token: {type(exc).__name__}") from None

        iss = claims.get("iss")
        if not isinstance(iss, str) or iss != self.issuer:
            raise AccessDenied("issuer mismatch")
        token_type = claims.get("type")
        if token_type is not None and token_type != "app":
            raise AccessDenied("not an application token")
        return claims

    def identity_from_claims(
        self,
        claims: dict[str, Any],
        *,
        ray_id: str | None = None,
        email_header: str | None = None,
    ) -> Identity:
        country = claims.get("country")
        country = country if isinstance(country, str) and _COUNTRY_RE.fullmatch(country) else None

        email = claims.get("email")
        if self.service_client_ids is not None:
            common_name = claims.get("common_name")
            if email or not isinstance(common_name, str):
                raise AccessDenied("not a service token")
            if common_name not in self.service_client_ids:
                raise AccessDenied("service token not allowed")
            if email_header is not None:
                raise AccessDenied("email header on a service token")
            return Identity(subject=common_name, kind="service", country=country, ray_id=ray_id)

        if isinstance(email, str) and email:
            # ASCII only: str.lower() maps e.g. KELVIN SIGN to "k", so a non-ASCII
            # address could lowercase onto an enrolled one.
            if not email.isascii() or not _EMAIL_RE.fullmatch(email):
                raise AccessDenied("malformed email claim")
            email = email.lower()
            if email_header is not None and email_header.strip().lower() != email:
                raise AccessDenied("email header does not match token")
            return Identity(subject=email, kind="user", email=email, country=country, ray_id=ray_id)

        common_name = claims.get("common_name")
        if isinstance(common_name, str) and common_name:
            if not self.allow_service_tokens:
                raise AccessDenied("service tokens are not allowed")
            if not _COMMON_NAME_RE.fullmatch(common_name):
                raise AccessDenied("malformed common_name claim")
            if email_header is not None:
                raise AccessDenied("email header on a service token")
            return Identity(subject=common_name, kind="service", country=country, ray_id=ray_id)

        raise AccessDenied("token has no email")

    async def authenticate(
        self,
        token: str | None,
        *,
        ray_id: str | None = None,
        email_header: str | None = None,
    ) -> Identity:
        if not token:
            raise AccessDenied("missing token")
        claims = await self.verify(token)
        return self.identity_from_claims(claims, ray_id=ray_id, email_header=email_header)
