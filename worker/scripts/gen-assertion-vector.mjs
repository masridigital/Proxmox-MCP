// Generates test/fixtures/assertion-vector.json: a TEST-ONLY Ed25519 key pair and one
// X-MCP-Identity JWS, so the Python broker tests can verify a token produced by the exact
// encoding this Worker uses. Ed25519 is deterministic, so test/assertion.test.ts re-signs the
// same inputs with src/assertion.ts and requires a byte-identical JWS.
//
// Run: npm run gen-vector   (only when the claim set changes; commit the result)
import { writeFileSync } from "node:fs";

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const pem = (label, der) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g).join("\n")}\n-----END ${label}-----\n`;

const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));

const body = JSON.stringify({ tool: "get_node_status", arguments: { node: "pve1" } });
const kid = "test-key-1";
const iat = 1767225600; // 2026-01-01T00:00:00Z, fixed so the vector is stable
const claims = {
  iss: "proxmox-mcp-worker",
  aud: "proxmox-broker",
  sub: "alice@example.com",
  iat,
  exp: iat + 60,
  jti: "00000000-0000-4000-8000-000000000001",
  ray: "8f00000000000000-EWR",
  req: Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body))).toString("hex"),
  method: "POST",
  path: "/v1/execute",
};
const header = { alg: "EdDSA", typ: "JWT", kid };
const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, new TextEncoder().encode(signingInput));

const vector = {
  _warning: "TEST ONLY. This key pair is public and must never be deployed or trusted anywhere.",
  description: "X-MCP-Identity cross-implementation vector (EdDSA/Ed25519 compact JWS).",
  private_key_pkcs8_pem: pem("PRIVATE KEY", pkcs8),
  public_key_spki_pem: pem("PUBLIC KEY", spki),
  public_key_raw_b64url: b64url(raw),
  kid,
  body,
  body_sha256: claims.req,
  header,
  claims,
  jws: `${signingInput}.${b64url(sig)}`,
  verify_at_unix: iat + 30,
};
const out = new URL("../test/fixtures/assertion-vector.json", import.meta.url);
writeFileSync(out, `${JSON.stringify(vector, null, 2)}\n`);
console.log(`wrote ${out.pathname}`);
