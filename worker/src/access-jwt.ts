// Cloudflare Access application token (Cf-Access-Jwt-Assertion) verification.
//
// RS256 only. Keys come from <team>/cdn-cgi/access/certs, cached per isolate with a TTL and
// refreshed early (rate limited) when a token names an unknown kid. Every claim check fails
// closed. Service-token JWTs (common_name claim, empty sub, no email) are refused: only
// people call this Worker.

import { b64urlDecode, decodeUtf8, isPlainObject, utf8 } from "./util";

export const LEEWAY_S = 60;
const JWKS_TTL_MS = 10 * 60_000;
const JWKS_MIN_REFRESH_MS = 30_000;
const MAX_TOKEN_LEN = 8192;
const MAX_JWKS_BYTES = 64 * 1024;
const JWKS_FAILURE_BACKOFF_MS = 5_000;
// Same shape the broker requires for the assertion `sub` (identity_assertion._EMAIL_RE), so a
// user the broker would refuse is refused here with a clear reason. ASCII is checked BEFORE
// lowercasing: String.prototype.toLowerCase folds U+212A KELVIN SIGN to "k" and U+0130 to
// "i\u0307", which would let an IdP-asserted "\u212Aelly@" act as "kelly@".
const RAW_EMAIL_RE = /^[\x21-\x7e]{3,254}$/;
const EMAIL_RE = /^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/;
// JOSE header members that carry or point at key material. We only ever use our own JWKS.
const FORBIDDEN_HEADERS = ["jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256"];

export class AuthError extends Error {
  constructor(
    public reason: string,
    public status: 401 | 403 | 503 = 401,
  ) {
    super(reason);
  }
}

export interface AccessIdentity {
  email: string;
  sub: string;
}

export interface AccessJwtOptions {
  teamDomain: string;
  audiences: string[];
  fetcher?: (url: string, init: RequestInit) => Promise<Response>;
  now?: () => number; // ms
}

interface CachedKeys {
  team: string;
  keys: Map<string, CryptoKey>;
  fetchedAt: number;
}

let cache: CachedKeys | null = null;
// One fetch in flight per isolate (a cold-start burst shares it) and the time of the last
// attempt, successful or not, so a failing or flooded endpoint is not hammered.
let inflight: Promise<Map<string, CryptoKey>> | null = null;
let lastAttempt = -Infinity;
let lastFailure = -Infinity;

/** Test hook: forget cached keys. */
export function resetJwksCache(): void {
  cache = null;
  inflight = null;
  lastAttempt = -Infinity;
  lastFailure = -Infinity;
}

function fetchKeysOnce(opts: AccessJwtOptions, now: number): Promise<Map<string, CryptoKey>> {
  if (inflight) return inflight;
  if (now - lastFailure < JWKS_FAILURE_BACKOFF_MS) return Promise.reject(new AuthError("jwks unavailable", 503));
  lastAttempt = now;
  const p = fetchKeys(opts, now).then(
    (keys) => {
      inflight = null;
      return keys;
    },
    (e: unknown) => {
      inflight = null;
      lastFailure = now;
      throw e;
    },
  );
  inflight = p;
  return p;
}

async function fetchKeys(opts: AccessJwtOptions, now: number): Promise<Map<string, CryptoKey>> {
  const doFetch = opts.fetcher ?? ((u: string, i: RequestInit) => fetch(u, i));
  let res: Response;
  try {
    res = await doFetch(`${opts.teamDomain}/cdn-cgi/access/certs`, {
      headers: { accept: "application/json" },
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    throw new AuthError("jwks unavailable", 503);
  }
  const text = res.status === 200 ? await res.text() : "";
  if (res.status !== 200 || text.length > MAX_JWKS_BYTES) throw new AuthError("jwks unavailable", 503);
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new AuthError("jwks unavailable", 503);
  }
  const keys = new Map<string, CryptoKey>();
  const list = isPlainObject(doc) && Array.isArray(doc.keys) ? doc.keys.slice(0, 20) : [];
  // A kid that appears twice is ambiguous: use neither.
  const kidCount = new Map<unknown, number>();
  for (const jwk of list) if (isPlainObject(jwk)) kidCount.set(jwk.kid, (kidCount.get(jwk.kid) ?? 0) + 1);
  for (const jwk of list) {
    if (!isPlainObject(jwk) || jwk.kty !== "RSA" || typeof jwk.kid !== "string" || !jwk.kid || typeof jwk.n !== "string") continue;
    if (kidCount.get(jwk.kid) !== 1) continue;
    if (jwk.use !== undefined && jwk.use !== "sig") continue;
    if (jwk.alg !== undefined && jwk.alg !== "RS256") continue;
    if (jwk.e !== "AQAB") continue; // 65537 only; a tiny exponent makes forgeries trivial
    try {
      if (b64urlDecode(jwk.n).length < 256) continue; // < 2048-bit modulus
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: "RSA", n: jwk.n, e: "AQAB", alg: "RS256", ext: true },
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"],
      );
      keys.set(jwk.kid, key);
    } catch {
      // skip unusable keys
    }
  }
  if (!keys.size) throw new AuthError("jwks unavailable", 503);
  cache = { team: opts.teamDomain, keys, fetchedAt: now };
  return keys;
}

async function keyFor(kid: string, opts: AccessJwtOptions, now: number): Promise<CryptoKey> {
  const fresh = cache && cache.team === opts.teamDomain && now - cache.fetchedAt < JWKS_TTL_MS;
  let keys = fresh ? cache!.keys : await fetchKeysOnce(opts, now);
  let key = keys.get(kid);
  if (!key && fresh && now - Math.max(cache!.fetchedAt, lastAttempt) >= JWKS_MIN_REFRESH_MS) {
    keys = await fetchKeysOnce(opts, now); // key rotation: refresh once, rate limited
    key = keys.get(kid);
  }
  if (!key) throw new AuthError("unknown kid");
  return key;
}

function parseJson(part: string): Record<string, unknown> {
  const value: unknown = JSON.parse(decodeUtf8(b64urlDecode(part)));
  if (!isPlainObject(value)) throw new Error("not an object");
  return value;
}

export async function verifyAccessJwt(token: string | null, opts: AccessJwtOptions): Promise<AccessIdentity> {
  if (!token) throw new AuthError("missing token");
  if (token.length > MAX_TOKEN_LEN) throw new AuthError("token too long");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => !p)) throw new AuthError("malformed token");
  const [h, p, s] = parts as [string, string, string];

  let header: Record<string, unknown>;
  let claims: Record<string, unknown>;
  let sig: Uint8Array;
  try {
    header = parseJson(h);
    claims = parseJson(p);
    sig = b64urlDecode(s);
  } catch {
    throw new AuthError("malformed token");
  }
  if (header.alg !== "RS256") throw new AuthError("bad alg");
  if (header.crit !== undefined) throw new AuthError("crit not supported");
  if (FORBIDDEN_HEADERS.some((k) => k in header)) throw new AuthError("unsupported header");
  if (header.typ !== undefined && header.typ !== "JWT") throw new AuthError("unsupported header");
  if (typeof header.kid !== "string" || !header.kid) throw new AuthError("missing kid");

  const nowMs = (opts.now ?? Date.now)();
  const key = await keyFor(header.kid, opts, nowMs);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, utf8(`${h}.${p}`));
  if (!ok) throw new AuthError("bad signature");

  const now = Math.floor(nowMs / 1000);
  if (claims.iss !== opts.teamDomain) throw new AuthError("bad iss");
  const aud = typeof claims.aud === "string" ? [claims.aud] : Array.isArray(claims.aud) ? claims.aud : [];
  if (!aud.some((a) => typeof a === "string" && opts.audiences.includes(a))) throw new AuthError("bad aud");
  if (typeof claims.exp !== "number" || now > claims.exp + LEEWAY_S) throw new AuthError("expired");
  if (typeof claims.iat !== "number" || claims.iat > now + LEEWAY_S) throw new AuthError("bad iat");
  if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || claims.nbf > now + LEEWAY_S)) {
    throw new AuthError("not yet valid");
  }
  if (claims.common_name !== undefined) throw new AuthError("service token not allowed", 403);
  // Access application tokens carry type "app"; "org" (team-domain session) tokens must not
  // be accepted by an application even if their audience were to match.
  if (claims.type !== undefined && claims.type !== "app") throw new AuthError("not an application token", 403);
  if (typeof claims.sub !== "string" || !claims.sub) throw new AuthError("missing sub", 403);
  if (typeof claims.email !== "string") throw new AuthError("missing email", 403);
  if (!RAW_EMAIL_RE.test(claims.email)) throw new AuthError("bad email", 403);
  const email = claims.email.toLowerCase();
  if (!EMAIL_RE.test(email)) throw new AuthError("bad email", 403);
  return { email, sub: claims.sub };
}

/** Optional second gate on top of the Access policy. Empty lists = allow. */
export function emailAllowed(email: string, emails: string[], domains: string[]): boolean {
  if (!emails.length && !domains.length) return true;
  if (emails.includes(email)) return true;
  const domain = email.slice(email.lastIndexOf("@") + 1);
  return domains.includes(domain);
}
