import { beforeEach, describe, expect, it } from "vitest";
import { AuthError, emailAllowed, resetJwksCache, verifyAccessJwt } from "../src/access-jwt";
import { b64urlEncode, utf8 } from "../src/util";
import { AUD, TEAM, type Issuer, installFetch, makeIssuer, userClaims } from "./helpers";

let issuer: Issuer;
const counter = { certs: 0 };
const opts = { teamDomain: TEAM, audiences: [AUD] };

async function reason(token: string | null): Promise<string> {
  try {
    await verifyAccessJwt(token, opts);
    return "accepted";
  } catch (e) {
    expect(e).toBeInstanceOf(AuthError);
    return (e as AuthError).reason;
  }
}

beforeEach(async () => {
  resetJwksCache();
  issuer = await makeIssuer();
  counter.certs = 0;
  installFetch(issuer, undefined, counter);
});

describe("Access JWT", () => {
  it("accepts a valid user token and lowercases the email", async () => {
    const id = await verifyAccessJwt(await issuer.sign(userClaims()), opts);
    expect(id.email).toBe("alice@example.com");
  });

  it("accepts aud as a plain string", async () => {
    expect(await reason(await issuer.sign(userClaims({ aud: AUD })))).toBe("accepted");
  });

  it("rejects a missing token", async () => {
    expect(await reason(null)).toBe("missing token");
  });

  it("rejects an expired token beyond the 60 s leeway", async () => {
    const now = Math.floor(Date.now() / 1000);
    expect(await reason(await issuer.sign(userClaims({ exp: now - 61 })))).toBe("expired");
    expect(await reason(await issuer.sign(userClaims({ exp: now - 30 })))).toBe("accepted");
  });

  it("rejects nbf and iat in the future", async () => {
    const now = Math.floor(Date.now() / 1000);
    expect(await reason(await issuer.sign(userClaims({ nbf: now + 120 })))).toBe("not yet valid");
    expect(await reason(await issuer.sign(userClaims({ iat: now + 120 })))).toBe("bad iat");
  });

  it("rejects the wrong audience", async () => {
    expect(await reason(await issuer.sign(userClaims({ aud: ["b".repeat(64)] })))).toBe("bad aud");
  });

  it("rejects the wrong issuer, including a trailing slash", async () => {
    expect(await reason(await issuer.sign(userClaims({ iss: "https://evil.cloudflareaccess.com" })))).toBe("bad iss");
    expect(await reason(await issuer.sign(userClaims({ iss: `${TEAM}/` })))).toBe("bad iss");
  });

  it("rejects alg none", async () => {
    const h = b64urlEncode(JSON.stringify({ alg: "none", kid: issuer.kid }));
    const p = b64urlEncode(JSON.stringify(userClaims()));
    expect(await reason(`${h}.${p}.`)).toBe("malformed token");
    expect(await reason(`${h}.${p}.AAAA`)).toBe("bad alg");
  });

  it("rejects HS256 key confusion (HMAC keyed with the public key)", async () => {
    const h = b64urlEncode(JSON.stringify({ alg: "HS256", kid: issuer.kid }));
    const p = b64urlEncode(JSON.stringify(userClaims()));
    const secret = utf8(JSON.stringify(issuer.jwks.keys[0]));
    const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(`${h}.${p}`)));
    expect(await reason(`${h}.${p}.${b64urlEncode(sig)}`)).toBe("bad alg");
  });

  it("rejects an unknown kid and a token signed by another key", async () => {
    expect(await reason(await issuer.sign(userClaims(), { kid: "other" }))).toBe("unknown kid");
    const other = await makeIssuer(issuer.kid);
    expect(await reason(await other.sign(userClaims()))).toBe("bad signature");
  });

  it("rejects a tampered payload", async () => {
    const [h, , s] = (await issuer.sign(userClaims())).split(".");
    const p = b64urlEncode(JSON.stringify(userClaims({ email: "mallory@example.com" })));
    expect(await reason(`${h}.${p}.${s}`)).toBe("bad signature");
  });

  it("rejects service tokens (common_name, empty sub, no email)", async () => {
    const svc = userClaims({ common_name: "abc.access", sub: "", email: undefined });
    delete svc.email;
    const err = await verifyAccessJwt(await issuer.sign(svc), opts).catch((e: AuthError) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect((err as AuthError).reason).toBe("service token not allowed");
    expect((err as AuthError).status).toBe(403);
  });

  it("requires sub and email", async () => {
    expect(await reason(await issuer.sign(userClaims({ sub: "" })))).toBe("missing sub");
    const c = userClaims();
    delete c.email;
    expect(await reason(await issuer.sign(c))).toBe("missing email");
    expect(await reason(await issuer.sign(userClaims({ email: "not-an-email" })))).toBe("bad email");
  });

  it("rejects crit headers and oversize tokens", async () => {
    expect(await reason(await issuer.sign(userClaims(), { crit: ["exp"] }))).toBe("crit not supported");
    expect(await reason("a".repeat(9000))).toBe("token too long");
  });

  it("caches the JWKS and refreshes once on key rotation", async () => {
    await verifyAccessJwt(await issuer.sign(userClaims()), opts);
    await verifyAccessJwt(await issuer.sign(userClaims()), opts);
    expect(counter.certs).toBe(1);
    // Rotation inside the 30 s refresh floor: no refetch, unknown kid.
    const rotated = await makeIssuer("kid-2");
    installFetch(rotated, undefined, counter);
    expect(await reason(await rotated.sign(userClaims()))).toBe("unknown kid");
    expect(counter.certs).toBe(1);
    // After the floor: one refresh picks up the new key.
    const later = Date.now() + 31_000;
    const id = await verifyAccessJwt(await rotated.sign(userClaims()), { ...opts, now: () => later });
    expect(id.email).toBe("alice@example.com");
    expect(counter.certs).toBe(2);
  });

  it("fails closed with 503 when the JWKS cannot be fetched", async () => {
    globalThis.fetch = (async () => new Response("down", { status: 502 })) as typeof fetch;
    const err = await verifyAccessJwt(await issuer.sign(userClaims()), opts).catch((e: AuthError) => e);
    expect((err as AuthError).status).toBe(503);
  });
});

describe("email gate", () => {
  it("allows everyone when no list is set", () => {
    expect(emailAllowed("a@x.com", [], [])).toBe(true);
  });
  it("matches exact emails and domains", () => {
    expect(emailAllowed("a@x.com", ["a@x.com"], [])).toBe(true);
    expect(emailAllowed("b@x.com", ["a@x.com"], [])).toBe(false);
    expect(emailAllowed("b@x.com", [], ["x.com"])).toBe(true);
    expect(emailAllowed("b@evilx.com", [], ["x.com"])).toBe(false);
  });
});
