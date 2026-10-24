"""H1 red team: token-level attacks on the Access JWT and the Worker identity assertion.

Each test is an attack that must be refused. They were written failing first,
then the verifiers were hardened (strict compact-JWS pre-parse, header and
claim allowlists, anchored regexes, ASCII-only identities, clock-step-safe
replay cache).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from jwt.algorithms import RSAAlgorithm

from proxmox_mcp.transport.access_jwt import AccessDenied, AccessVerifier
from proxmox_mcp.transport.identity_assertion import (
    AssertionDenied,
    IdentityAssertionVerifier,
    ReplayCache,
)
from proxmox_mcp.transport.jws_strict import MalformedJws, parse_compact

TEAM = "https://team.cloudflareaccess.com"
AUD = "a" * 64
SERVICE_ID = "0123456789abcdef.access"
USER = "alice@example.com"
EMPTY_SHA = hashlib.sha256(b"").hexdigest()

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
WORKER_KEY = ed25519.Ed25519PrivateKey.generate()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _sign_raw(header_json: bytes, payload_json: bytes, key=WORKER_KEY) -> str:
    """Sign arbitrary header/payload BYTES (lets a test craft duplicate keys etc.)."""
    signing_input = f"{_b64(header_json)}.{_b64(payload_json)}".encode()
    return f"{signing_input.decode()}.{_b64(key.sign(signing_input))}"


# ---- identity assertion ----------------------------------------------------


def a_claims(**over) -> dict:
    now = int(time.time())
    c = {
        "iss": "proxmox-mcp-worker",
        "aud": "proxmox-broker",
        "sub": USER,
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        "ray": "8f00000000000000-IAD",
        "req": EMPTY_SHA,
        "method": "GET",
        "path": "/v1/catalog",
    }
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def a_token(headers: dict | None = None, **over) -> str:
    return jwt.encode(
        a_claims(**over), WORKER_KEY, algorithm="EdDSA", headers={"kid": "k1", **(headers or {})}
    )


def verify_assertion(token: str, verifier: IdentityAssertionVerifier | None = None):
    v = verifier or IdentityAssertionVerifier(WORKER_KEY.public_key())
    return v.verify(token, body=b"", method="GET", path="/v1/catalog")


def test_baseline_worker_shaped_assertion_accepted():
    # Exactly what worker/src/assertion.ts emits: header {alg, typ, kid}.
    assert verify_assertion(a_token()).identity.subject == USER


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda h, p, s: f"{h}.{p}.{s}==", id="padding-on-signature"),
        pytest.param(lambda h, p, s: f"{h}=.{p}.{s}", id="padding-on-header"),
        pytest.param(lambda h, p, s: f"{h}.{p}.{s} ", id="trailing-space"),
        pytest.param(lambda h, p, s: f" {h}.{p}.{s}", id="leading-space"),
        pytest.param(lambda h, p, s: f"{h}.{p}.{s}\n", id="trailing-newline"),
        pytest.param(lambda h, p, s: f"{h}.{p}.{s[:5]}+{s[6:]}", id="std-b64-alphabet"),
        pytest.param(lambda h, p, s: f"{h}.{p}.{s[:5]}\xe9{s[5:]}", id="latin1-byte"),
        pytest.param(lambda h, p, s: f"{h}.{p}.", id="empty-signature"),
        pytest.param(lambda h, p, s: f"{h}..{s}", id="empty-payload"),
        pytest.param(lambda h, p, s: f"{h}.{p}.{s}.{s}", id="four-segments"),
    ],
)
def test_assertion_encoding_malleability_refused(mutate):
    """One signed assertion must have exactly one accepted spelling."""
    h, p, s = a_token().split(".")
    with pytest.raises(AssertionDenied):
        verify_assertion(mutate(h, p, s))


def test_assertion_noncanonical_trailing_bits_refused():
    """Ed25519 signatures are 64 bytes = 86 base64url chars with 4 unused bits in
    the last one; flipping those bits decodes to the same bytes. Refuse it."""
    h, p, s = a_token().split(".")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(s[-1])
    twin = alphabet[last ^ 0b0001]  # same 2 significant bits, different padding bits
    assert base64.urlsafe_b64decode(s + "==") == base64.urlsafe_b64decode(s[:-1] + twin + "==")
    with pytest.raises(AssertionDenied):
        verify_assertion(f"{h}.{p}.{s[:-1]}{twin}")


@pytest.mark.parametrize(
    "header",
    [
        {"crit": ["b64"], "b64": False},
        {"cty": "JWT"},  # nested JWS
        {"zip": "DEF"},
        {"x5t": "abc"},
        {"jku": "https://evil.example.com/jwks"},
        {"kid": "../../etc/passwd"},
        {"kid": "https://evil.example.com/key"},
        {"typ": "at+jwt"},
        {"enc": "A256GCM"},
    ],
)
def test_assertion_header_allowlist(header):
    with pytest.raises(AssertionDenied):
        verify_assertion(a_token(headers=header))


def test_assertion_b64_true_header_refused():
    # PyJWT's encoder drops b64=true, so sign the header bytes by hand.
    token = _sign_raw(b'{"alg":"EdDSA","typ":"JWT","b64":true}', json.dumps(a_claims()).encode())
    with pytest.raises(AssertionDenied):
        verify_assertion(token)


def test_assertion_duplicate_header_keys_refused():
    payload = json.dumps(a_claims()).encode()
    header = b'{"alg":"EdDSA","typ":"JWT","alg":"EdDSA"}'
    with pytest.raises(AssertionDenied):
        verify_assertion(_sign_raw(header, payload))


def test_assertion_duplicate_claims_refused():
    """{"sub": victim, ..., "sub": attacker}: parsers disagree on which wins."""
    c = a_claims()
    body = json.dumps(c)[:-1] + ', "sub": "mallory@example.com"}'
    token = _sign_raw(b'{"alg":"EdDSA","typ":"JWT"}', body.encode())
    with pytest.raises(AssertionDenied):
        verify_assertion(token)


def test_assertion_nan_claim_refused():
    c = json.dumps(a_claims()).replace('"iat": ', '"iat": NaN, "x_iat": ')
    with pytest.raises(AssertionDenied):
        verify_assertion(_sign_raw(b'{"alg":"EdDSA","typ":"JWT"}', c.encode()))


def test_assertion_unknown_claims_refused():
    with pytest.raises(AssertionDenied):
        verify_assertion(a_token(mode="rw"))
    with pytest.raises(AssertionDenied):
        verify_assertion(a_token(groups=["admins"]))


@pytest.mark.parametrize(
    "claim,value",
    [
        ("sub", USER + "\n"),  # `$` matches before a trailing newline
        ("sub", "Kate@example.com"),  # KELVIN SIGN
        ("sub", "alice@example.com "),
        ("jti", "abcdefgh1234\n"),
        ("req", EMPTY_SHA + "\n"),
        ("method", "get"),
        ("path", "/v1/catalog/"),
        ("aud", ["proxmox-broker"]),
        ("iat", True),
        ("exp", "9999999999"),
    ],
)
def test_assertion_claim_edge_cases(claim, value):
    with pytest.raises(AssertionDenied):
        verify_assertion(a_token(**{claim: value}))


def test_assertion_oversize_refused_before_parsing():
    with pytest.raises(AssertionDenied):
        verify_assertion("a" * 5000 + ".b.c")


def test_replay_survives_wall_clock_step_back():
    """NTP/w32time steps the wall clock back after the monotonic replay window
    passed: the assertion is 'valid' again by exp, so its jti must still be held."""
    mono = [0.0]
    wall = [1_000_000.0]
    cache = ReplayCache(clock=lambda: mono[0], wall_clock=lambda: wall[0])
    v = IdentityAssertionVerifier(WORKER_KEY.public_key(), replay_cache=cache, now=lambda: wall[0])
    iat = int(wall[0])
    token = a_token(iat=iat, exp=iat + 60)
    verify_assertion(token, v)
    # Time passes normally; the token expired and the window elapsed.
    mono[0] += 500
    wall[0] += 500
    with pytest.raises(AssertionDenied):
        verify_assertion(token, v)  # expired
    # Wall clock steps back 8 minutes: token is inside exp+leeway again.
    wall[0] -= 480
    with pytest.raises(AssertionDenied, match="replay"):
        verify_assertion(token, v)


def test_replay_cache_still_evicts_when_clocks_agree():
    mono = [0.0]
    wall = [1_000_000.0]
    cache = ReplayCache(
        window=120, max_entries=1, clock=lambda: mono[0], wall_clock=lambda: wall[0]
    )
    cache.add("jti-00000001", not_after=wall[0] + 90)
    mono[0] += 121
    wall[0] += 121
    cache.add("jti-00000002", not_after=wall[0] + 90)  # first one evicted; no "full"
    assert len(cache) == 1


# ---- Access JWT ---------------------------------------------------------------


class Jwks:
    def __init__(self) -> None:
        jwk = json.loads(RSAAlgorithm.to_jwk(RSA_KEY.public_key()))
        jwk.update({"kid": "k1", "alg": "RS256", "use": "sig"})
        self.doc = {"keys": [jwk]}
        self.calls = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, json=self.doc)


def access(jwks: Jwks | None = None, **kw) -> AccessVerifier:
    j = jwks or Jwks()
    return AccessVerifier(
        TEAM, AUD, http_client=httpx.AsyncClient(transport=httpx.MockTransport(j.handler)), **kw
    )


def c_claims(**over) -> dict:
    now = int(time.time())
    c = {
        "aud": [AUD],
        "email": USER,
        "iss": TEAM,
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "type": "app",
        "sub": "6f0e1f6a-0000-4000-8000-000000000000",
    }
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def c_token(headers: dict | None = None, **over) -> str:
    return jwt.encode(
        c_claims(**over), RSA_KEY, algorithm="RS256", headers={"kid": "k1", **(headers or {})}
    )


async def test_access_baseline():
    assert (await access().authenticate(c_token())).subject == USER


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda h, p, s: f"{h}.{p}.{s}==", id="padding"),
        pytest.param(lambda h, p, s: f"{h}.{p}.{s[:5]}\xe9{s[5:]}", id="latin1"),
        pytest.param(lambda h, p, s: f"{h}.{p}.{s[:5]}/{s[6:]}", id="std-b64-alphabet"),
    ],
)
async def test_access_encoding_malleability_refused(mutate):
    h, p, s = c_token().split(".")
    with pytest.raises(AccessDenied):
        await access().authenticate(mutate(h, p, s))


@pytest.mark.parametrize(
    "header",
    [
        {"crit": ["b64"], "b64": False},
        {"cty": "JWT"},
        {"zip": "DEF"},
        {"x5c": ["MIIB"]},
        {"typ": "at+jwt"},
        {"kid": "../../../etc/passwd"},
        {"kid": "https://evil.example.com/k"},
    ],
)
async def test_access_header_tricks(header):
    with pytest.raises(AccessDenied):
        await access().authenticate(c_token(headers=header))


async def test_access_duplicate_claims_refused():
    payload = json.dumps(c_claims())[:-1] + ', "email": "mallory@example.com"}'
    header = _b64(b'{"alg":"RS256","kid":"k1","typ":"JWT"}')
    signing_input = f"{header}.{_b64(payload.encode())}"
    sig = jwt.get_algorithm_by_name("RS256").sign(signing_input.encode(), RSA_KEY)
    with pytest.raises(AccessDenied):
        await access().authenticate(f"{signing_input}.{_b64(sig)}")


@pytest.mark.parametrize(
    "email",
    [
        USER + "\n",  # `$` before trailing newline
        "Kate@example.com",  # KELVIN SIGN lowercases to ASCII 'k'
        "ALİCE@example.com",  # dotted capital I: lower() changes length
        "alice@example.com​",  # zero-width space
    ],
)
async def test_access_email_must_be_ascii_and_anchored(email):
    with pytest.raises(AccessDenied):
        await access().authenticate(c_token(email=email))


async def test_access_service_common_name_anchored():
    v = access(service_client_ids=[SERVICE_ID])
    token = c_token(email=None, sub="", common_name=SERVICE_ID + "\n")
    with pytest.raises(AccessDenied):
        await v.authenticate(token)


@pytest.mark.parametrize("iss", [TEAM + "/", TEAM + "//", TEAM.upper()])
async def test_access_issuer_exact(iss):
    with pytest.raises(AccessDenied):
        await access().authenticate(c_token(iss=iss))


async def test_access_aud_string_or_list_both_work():
    v = access()
    assert (await v.authenticate(c_token(aud=AUD))).subject == USER
    assert (await v.authenticate(c_token(aud=["x", AUD]))).subject == USER
    with pytest.raises(AccessDenied):
        await v.authenticate(c_token(aud=AUD + "x"))


async def test_access_forged_kid_flood_is_one_fetch():
    """JWKS fetch amplification: many forged kids cost one refetch per minute."""
    j = Jwks()
    v = access(j)
    await v.prefetch()
    for i in range(50):
        with pytest.raises(AccessDenied):
            await v.authenticate(c_token(headers={"kid": f"forged-{i}"}))
    assert j.calls <= 2


# ---- the shared strict parser itself -----------------------------------------


def test_parse_compact_rejects_non_object_segments():
    for header in (b"[]", b'"x"', b"1", b"null"):
        tok = f"{_b64(header)}.{_b64(b'{}')}.{_b64(b'sig')}"
        with pytest.raises(MalformedJws):
            parse_compact(tok, max_bytes=4096, alg="EdDSA", allowed_header=frozenset({"alg"}))
    header = _b64(b'{"alg":"EdDSA"}')
    tok = f"{header}.{_b64(b'[1]')}.{_b64(b'sig')}"
    with pytest.raises(MalformedJws):
        parse_compact(tok, max_bytes=4096, alg="EdDSA", allowed_header=frozenset({"alg"}))
