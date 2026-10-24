"""Strict pre-parse of a compact JWS, run before PyJWT sees the token.

PyJWT is lenient in ways a verifier at a trust boundary should not be:

* base64url decoding goes through ``base64.urlsafe_b64decode``, which accepts
  ``=`` padding and ignores the unused low bits of the last character, so one
  signed token has many accepted spellings (malleability: anything keyed on the
  token string, a log or a cache, can be dodged);
* JSON is parsed with ``json.loads``: duplicate keys silently resolve to the last
  one (``{"sub": victim, "sub": attacker}`` means different things to different
  parsers) and ``NaN`` / ``Infinity`` are accepted;
* unknown JOSE header parameters (``cty``, ``zip``, ``b64`` without ``crit``...)
  are ignored rather than refused.

``parse_compact`` enforces: ASCII only, exactly three non-empty segments, the
base64url alphabet with no padding, canonical encoding (re-encoding the decoded
bytes gives back the same text), header and payload that are JSON objects with
unique keys and no non-finite numbers, a fixed ``alg``, ``typ`` either absent or
``JWT``, and a header-parameter allowlist. It does NOT verify the signature;
callers still run ``jwt.decode`` with a pinned algorithm and key.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

_SEGMENT_RE = re.compile(r"[A-Za-z0-9_-]+")


class MalformedJws(ValueError):
    """The token is not a canonical compact JWS. The message is for logs only."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise MalformedJws("duplicate JSON key")
        out[key] = value
    return out


def _no_constants(_: str) -> Any:
    raise MalformedJws("non-finite number")


def _b64decode_canonical(segment: str) -> bytes:
    if not _SEGMENT_RE.fullmatch(segment) or len(segment) % 4 == 1:
        raise MalformedJws("bad base64url segment")
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError):
        raise MalformedJws("bad base64url segment") from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise MalformedJws("non-canonical base64url")
    return raw


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        doc = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constants
        )
    except MalformedJws:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise MalformedJws("segment is not JSON") from None
    if not isinstance(doc, dict):
        raise MalformedJws("segment is not a JSON object")
    return doc


def parse_compact(
    token: str,
    *,
    max_bytes: int,
    alg: str,
    allowed_header: frozenset[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(header, payload) of a canonical compact JWS, or MalformedJws."""
    if not isinstance(token, str) or not token or len(token) > max_bytes:
        raise MalformedJws("missing or oversized token")
    if not token.isascii():
        raise MalformedJws("non-ASCII token")
    parts = token.split(".")
    if len(parts) != 3:
        raise MalformedJws("not a compact JWS")
    header_seg, payload_seg, signature_seg = parts
    header = _json_object(_b64decode_canonical(header_seg))
    if header.get("alg") != alg:
        raise MalformedJws("algorithm not allowed")
    if set(header) - allowed_header:
        raise MalformedJws("header parameter not allowed")
    if "typ" in header and header["typ"] != "JWT":
        raise MalformedJws("typ not allowed")
    payload = _json_object(_b64decode_canonical(payload_seg))
    _b64decode_canonical(signature_seg)
    return header, payload
