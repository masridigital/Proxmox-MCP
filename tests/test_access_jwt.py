"""Cloudflare Access JWT verifier: offline, against a locally generated RSA key."""

from __future__ import annotations

import base64
import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from proxmox_mcp.transport import access_jwt
from proxmox_mcp.transport.access_jwt import (
    AccessConfigError,
    AccessDenied,
    AccessUnavailable,
    AccessVerifier,
)

TEAM = "https://team.cloudflareaccess.com"
AUD = "a" * 64
SERVICE_ID = "0123456789abcdef.access"


def _rsa(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


KEY = _rsa()
OTHER_KEY = _rsa()


def jwk_of(key: rsa.RSAPrivateKey, kid: str) -> dict:
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return jwk


def claims(**over) -> dict:
    now = int(time.time())
    base = {
        "aud": [AUD],
        "email": "Alice@Example.com",
        "exp": now + 600,
        "iat": now,
        "nbf": now,
        "iss": TEAM,
        "type": "app",
        "identity_nonce": "n",
        "sub": "6f0e1f6a-0000-4000-8000-000000000000",
        "country": "US",
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def sign(c: dict, key=KEY, kid: str = "k1", alg: str = "RS256") -> str:
    return jwt.encode(c, key, algorithm=alg, headers={"kid": kid})


class Jwks:
    """Fake https://<team>/cdn-cgi/access/certs endpoint."""

    def __init__(self, keys: list[dict]):
        self.keys = keys
        self.calls = 0
        self.fail = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        assert str(request.url) == f"{TEAM}/cdn-cgi/access/certs"
        self.calls += 1
        if self.fail:
            return httpx.Response(500)
        return httpx.Response(200, json={"keys": self.keys, "public_cert": {}, "public_certs": []})


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def jwks():
    return Jwks([jwk_of(KEY, "k1")])


@pytest.fixture
def clock():
    return Clock()


def make(jwks: Jwks, clock: Clock | None = None, **kw) -> AccessVerifier:
    client = httpx.AsyncClient(transport=httpx.MockTransport(jwks.handler))
    return AccessVerifier(TEAM, AUD, http_client=client, clock=clock or Clock(), **kw)


async def test_valid_user_token(jwks):
    v = make(jwks)
    ident = await v.authenticate(sign(claims()), ray_id="8f00000000000000-IAD")
    assert ident.kind == "user"
    assert ident.subject == ident.email == "alice@example.com"
    assert ident.country == "US" and ident.ray_id == "8f00000000000000-IAD"


async def test_trailing_slash_team_domain_and_aud_list(jwks):
    client = httpx.AsyncClient(transport=httpx.MockTransport(jwks.handler))
    v = AccessVerifier(TEAM + "/", f"other, {AUD}", http_client=client)
    assert v.issuer == TEAM
    assert (await v.authenticate(sign(claims()))).subject == "alice@example.com"


async def test_expired(jwks):
    old = int(time.time()) - 3600
    with pytest.raises(AccessDenied):
        await make(jwks).verify(sign(claims(exp=old, iat=old - 600, nbf=old - 600)))


async def test_leeway_is_small(jwks):
    now = int(time.time())
    # 30 s past exp: inside the 60 s leeway
    await make(jwks).verify(sign(claims(exp=now - 30, iat=now - 600, nbf=now - 600)))
    with pytest.raises(AccessDenied):
        await make(jwks).verify(sign(claims(exp=now - 120, iat=now - 600, nbf=now - 600)))


async def test_not_yet_valid(jwks):
    future = int(time.time()) + 600
    with pytest.raises(AccessDenied):
        await make(jwks).verify(sign(claims(nbf=future, iat=future)))


@pytest.mark.parametrize("missing", ["exp", "iat", "nbf", "iss", "aud"])
async def test_required_claims(jwks, missing):
    c = claims()
    del c[missing]
    with pytest.raises(AccessDenied):
        await make(jwks).verify(sign(c))


async def test_wrong_audience(jwks):
    with pytest.raises(AccessDenied):
        await make(jwks).verify(sign(claims(aud=["b" * 64])))


@pytest.mark.parametrize(
    "iss",
    [
        "https://evil.cloudflareaccess.com",
        "https://team.cloudflareaccess.com.evil.com",
        "http://team.cloudflareaccess.com",
        "https://team.cloudflareaccess.com/x",
    ],
)
async def test_wrong_issuer(jwks, iss):
    with pytest.raises(AccessDenied, match="issuer"):
        await make(jwks).verify(sign(claims(iss=iss)))


async def test_org_token_type_refused(jwks):
    with pytest.raises(AccessDenied):
        await make(jwks).verify(sign(claims(type="org")))


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


async def test_alg_none(jwks):
    token = f"{_b64({'alg': 'none', 'kid': 'k1'})}.{_b64(claims())}."
    with pytest.raises(AccessDenied, match="algorithm"):
        await make(jwks).verify(token)
    assert jwks.calls == 0  # refused before any key lookup


async def test_hs256_key_confusion(jwks):
    """HS256 signed with the public key PEM as the HMAC secret must not verify."""
    pem = KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = _b64({"alg": "HS256", "kid": "k1", "typ": "JWT"})
    body = _b64(claims())
    import hashlib
    import hmac

    sig = hmac.new(pem, f"{header}.{body}".encode(), hashlib.sha256).digest()
    token = f"{header}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    with pytest.raises(AccessDenied, match="algorithm"):
        await make(jwks).verify(token)


async def test_rs256_header_with_wrong_key(jwks):
    with pytest.raises(AccessDenied):
        await make(jwks).verify(sign(claims(), key=OTHER_KEY, kid="k1"))


async def test_unknown_kid_refetch_rate_limited(jwks, clock):
    v = make(jwks, clock)
    await v.verify(sign(claims()))
    assert jwks.calls == 1
    for _ in range(5):
        with pytest.raises(AccessDenied, match="unknown kid"):
            await v.verify(sign(claims(), key=OTHER_KEY, kid="k2"))
    assert jwks.calls == 2  # one refetch, not five
    # Key rotation: after the interval the new key is picked up.
    jwks.keys.append(jwk_of(OTHER_KEY, "k2"))
    clock.t += 61
    await v.verify(sign(claims(), key=OTHER_KEY, kid="k2"))
    assert jwks.calls == 3


async def test_jwks_cached_until_ttl(jwks, clock):
    v = make(jwks, clock)
    for _ in range(3):
        await v.verify(sign(claims()))
    assert jwks.calls == 1
    clock.t += access_jwt.JWKS_TTL_SECONDS + 1
    await v.verify(sign(claims()))
    assert jwks.calls == 2


async def test_jwks_down_fails_closed(jwks, clock):
    jwks.fail = True
    with pytest.raises(AccessUnavailable):
        await make(jwks, clock).verify(sign(claims()))


async def test_stale_keys_used_when_refresh_fails(jwks, clock):
    v = make(jwks, clock)
    await v.verify(sign(claims()))
    jwks.fail = True
    clock.t += access_jwt.JWKS_TTL_SECONDS + 1
    await v.verify(sign(claims()))  # still within MAX_STALE
    clock.t += access_jwt.MAX_STALE_SECONDS
    with pytest.raises(AccessUnavailable):
        await v.verify(sign(claims()))


async def test_weak_and_private_jwks_entries(clock):
    weak = _rsa(1024)
    private_jwk = json.loads(RSAAlgorithm.to_jwk(KEY))  # includes "d"
    private_jwk.update({"kid": "k1"})
    jwks = Jwks([jwk_of(weak, "weak"), private_jwk])
    v = make(jwks, clock)
    await v.verify(sign(claims()))  # private params ignored, public half kept
    with pytest.raises(AccessDenied):
        await v.verify(sign(claims(), key=weak, kid="weak"))


async def test_missing_email(jwks):
    with pytest.raises(AccessDenied, match="no email"):
        await make(jwks).authenticate(sign(claims(email=None)))


async def test_email_header_must_match(jwks):
    v = make(jwks)
    await v.authenticate(sign(claims()), email_header="alice@example.com")
    with pytest.raises(AccessDenied):
        await v.authenticate(sign(claims()), email_header="bob@example.com")


async def test_service_token_disabled_by_default(jwks):
    token = sign(claims(email=None, sub="", common_name=SERVICE_ID))
    with pytest.raises(AccessDenied, match="service tokens"):
        await make(jwks).authenticate(token)


async def test_service_token_enabled(jwks):
    token = sign(claims(email=None, sub="", common_name=SERVICE_ID))
    ident = await make(jwks, allow_service_tokens=True).authenticate(token)
    assert ident.kind == "service" and ident.subject == SERVICE_ID and ident.email is None


async def test_broker_mode_pins_service_client_id(jwks):
    v = make(jwks, service_client_ids=[SERVICE_ID])
    ok = sign(claims(email=None, sub="", common_name=SERVICE_ID))
    assert (await v.authenticate(ok)).kind == "service"
    with pytest.raises(AccessDenied, match="not allowed"):
        await v.authenticate(sign(claims(email=None, sub="", common_name="other.access")))
    with pytest.raises(AccessDenied, match="not a service token"):
        await v.authenticate(sign(claims()))  # a person's token is not the Worker


async def test_missing_and_malformed_tokens(jwks):
    v = make(jwks)
    for token in (None, "", "abc", "a.b", "a.b.c.d", "x" * 9000):
        with pytest.raises(AccessDenied):
            await v.authenticate(token)


@pytest.mark.parametrize(
    "team",
    [
        "",
        "team.cloudflareaccess.com",
        "http://team.cloudflareaccess.com",
        "https://team.cloudflareaccess.com/path",
        "https://user@team.cloudflareaccess.com",
        "https://team.cloudflareaccess.com:8443",
        "https://team.cloudflareaccess.com?x=1",
    ],
)
def test_bad_team_domain_refuses_to_start(team):
    with pytest.raises(AccessConfigError):
        AccessVerifier(team, AUD)


@pytest.mark.parametrize("aud", ["", " , ", "bad aud"])
def test_bad_aud_refuses_to_start(aud):
    with pytest.raises(AccessConfigError):
        AccessVerifier(TEAM, aud)


def test_from_env_missing_config(monkeypatch):
    monkeypatch.delenv("CF_ACCESS_TEAM_DOMAIN", raising=False)
    monkeypatch.delenv("CF_ACCESS_AUD", raising=False)
    with pytest.raises(AccessConfigError):
        AccessVerifier.from_env()
    monkeypatch.setenv("CF_ACCESS_TEAM_DOMAIN", TEAM)
    monkeypatch.setenv("CF_ACCESS_AUD", AUD)
    monkeypatch.delenv("BROKER_ALLOWED_SERVICE_CLIENT_IDS", raising=False)
    with pytest.raises(AccessConfigError):
        AccessVerifier.for_broker_from_env()
    monkeypatch.setenv("BROKER_ALLOWED_SERVICE_CLIENT_IDS", SERVICE_ID)
    assert AccessVerifier.for_broker_from_env().service_client_ids == {SERVICE_ID}
