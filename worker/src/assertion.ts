// X-MCP-Identity: compact JWS (EdDSA / Ed25519) that tells the broker who the caller is and
// binds that statement to one exact request (method, path, sha256 of the body bytes) for 60 s.
// The private key is a Worker secret (PKCS8 PEM); the broker holds only the public key.

import { b64urlDecode, b64urlEncode, sha256Hex, utf8 } from "./util";

export const ASSERTION_TTL_S = 60;
export const ASSERTION_ISS = "proxmox-mcp-worker";
export const ASSERTION_AUD = "proxmox-broker";

export interface AssertionClaims {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  exp: number;
  jti: string;
  ray: string;
  req: string;
  method: string;
  path: string;
}

let keyCache: { pem: string; key: Promise<CryptoKey> } | null = null;

function pemToDer(pem: string): Uint8Array {
  const m = /-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----/.exec(pem);
  if (!m) throw new Error("IDENTITY_SIGNING_KEY is not a PKCS8 PEM");
  const b64 = m[1]!.replace(/\s+/g, "");
  return b64urlDecode(b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
}

export function importSigningKey(pem: string): Promise<CryptoKey> {
  if (keyCache?.pem === pem) return keyCache.key;
  const key = crypto.subtle.importKey("pkcs8", pemToDer(pem), { name: "Ed25519" }, false, ["sign"]);
  keyCache = { pem, key };
  key.catch(() => {
    if (keyCache?.key === key) keyCache = null;
  });
  return key;
}

export interface SignInput {
  pem: string;
  kid: string;
  sub: string;
  method: string;
  path: string;
  body: Uint8Array; // exact bytes sent; empty for GET
  ray: string;
  now?: number; // seconds, tests only
  jti?: string; // tests only
}

export async function buildClaims(input: SignInput): Promise<AssertionClaims> {
  const iat = input.now ?? Math.floor(Date.now() / 1000);
  return {
    iss: ASSERTION_ISS,
    aud: ASSERTION_AUD,
    sub: input.sub.toLowerCase(),
    iat,
    exp: iat + ASSERTION_TTL_S,
    jti: input.jti ?? crypto.randomUUID(),
    ray: input.ray,
    req: await sha256Hex(input.body),
    method: input.method.toUpperCase(),
    path: input.path,
  };
}

export async function signAssertion(input: SignInput): Promise<{ jws: string; claims: AssertionClaims }> {
  const key = await importSigningKey(input.pem);
  const claims = await buildClaims(input);
  const header = { alg: "EdDSA", typ: "JWT", kid: input.kid };
  const signingInput = `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(claims))}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, utf8(signingInput)));
  return { jws: `${signingInput}.${b64urlEncode(sig)}`, claims };
}
