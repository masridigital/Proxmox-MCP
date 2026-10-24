import { describe, expect, it } from "vitest";
import vector from "./fixtures/assertion-vector.json";
import { ASSERTION_TTL_S, signAssertion } from "../src/assertion";
import { b64urlDecode, utf8 } from "../src/util";
import { verifyIdentity } from "./helpers";

describe("X-MCP-Identity assertion", () => {
  it("reproduces the committed cross-language vector byte for byte", async () => {
    const { jws, claims } = await signAssertion({
      pem: vector.private_key_pkcs8_pem,
      kid: vector.kid,
      sub: vector.claims.sub,
      method: vector.claims.method,
      path: vector.claims.path,
      body: utf8(vector.body),
      ray: vector.claims.ray,
      now: vector.claims.iat,
      jti: vector.claims.jti,
    });
    expect(claims).toEqual(vector.claims);
    expect(jws).toBe(vector.jws);
  });

  it("uses header {alg: EdDSA, typ: JWT, kid} and a 60 s lifetime", async () => {
    const { jws, claims } = await signAssertion({
      pem: vector.private_key_pkcs8_pem,
      kid: "k1",
      sub: "Bob@Example.COM",
      method: "get",
      path: "/v1/catalog",
      body: new Uint8Array(0),
      ray: "",
    });
    const header = JSON.parse(new TextDecoder().decode(b64urlDecode(jws.split(".")[0]!)));
    expect(header).toEqual({ alg: "EdDSA", typ: "JWT", kid: "k1" });
    expect(claims.exp - claims.iat).toBe(ASSERTION_TTL_S);
    expect(claims.sub).toBe("bob@example.com");
    expect(claims.method).toBe("GET");
    // sha256 of the empty body
    expect(claims.req).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(claims.jti).toMatch(/^[0-9a-f-]{36}$/);
    await expect(verifyIdentity(jws, new Uint8Array(0), "GET", "/v1/catalog")).resolves.toBeTruthy();
  });

  it("binds the body: a different body fails verification", async () => {
    const body = utf8('{"tool":"a","arguments":{}}');
    const { jws } = await signAssertion({ pem: vector.private_key_pkcs8_pem, kid: "k", sub: "a@x.com", method: "POST", path: "/v1/execute", body, ray: "" });
    await expect(verifyIdentity(jws, body, "POST", "/v1/execute")).resolves.toBeTruthy();
    await expect(verifyIdentity(jws, utf8('{"tool":"b","arguments":{}}'), "POST", "/v1/execute")).rejects.toThrow("req");
    await expect(verifyIdentity(jws, body, "POST", "/v1/catalog")).rejects.toThrow("method/path");
  });

  it("generates a fresh jti per assertion", async () => {
    const a = await signAssertion({ pem: vector.private_key_pkcs8_pem, kid: "k", sub: "a@x.com", method: "GET", path: "/v1/catalog", body: new Uint8Array(0), ray: "" });
    const b = await signAssertion({ pem: vector.private_key_pkcs8_pem, kid: "k", sub: "a@x.com", method: "GET", path: "/v1/catalog", body: new Uint8Array(0), ray: "" });
    expect(a.claims.jti).not.toBe(b.claims.jti);
  });

  it("refuses a key that is not PKCS8 PEM", async () => {
    await expect(
      signAssertion({ pem: "not a key", kid: "k", sub: "a@x.com", method: "GET", path: "/", body: new Uint8Array(0), ray: "" }),
    ).rejects.toThrow();
  });
});
