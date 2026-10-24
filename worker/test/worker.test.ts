import { beforeEach, describe, expect, it, vi } from "vitest";
import worker, { MAX_REQUEST_BYTES, handle } from "../src/index";
import { resetJwksCache } from "../src/access-jwt";
import { resetCatalogCache } from "../src/tools";
import { HOST, type Issuer, callTool, ctx, installFetch, makeEnv, makeIssuer, mcpRequest, rpc, userClaims } from "./helpers";

let issuer: Issuer;
let token: string;

beforeEach(async () => {
  resetJwksCache();
  resetCatalogCache();
  issuer = await makeIssuer();
  installFetch(issuer);
  token = await issuer.sign(userClaims());
});

async function send(req: Request, env = makeEnv()) {
  const res = await handle(req, env, ctx);
  const text = await res.text();
  return { res, body: text ? JSON.parse(text) : null };
}

const MODERN_META = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const modernHeaders = (method: string, name?: string): Record<string, string> => ({
  "mcp-protocol-version": "2026-07-28",
  "mcp-method": method,
  ...(name ? { "mcp-name": name } : {}),
});

describe("HTTP surface", () => {
  it("answers 404 off /mcp and 405 for GET /mcp", async () => {
    expect((await send(mcpRequest(null, { url: `https://${HOST}/`, method: "GET" }))).res.status).toBe(404);
    const { res } = await send(mcpRequest(null, { method: "GET", token }));
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
  });

  it("returns 401 with WWW-Authenticate when unauthenticated", async () => {
    const { res, body } = await send(mcpRequest(rpc("tools/list")));
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(
      `Bearer realm="proxmox-mcp", resource_metadata="https://${HOST}/.well-known/oauth-protected-resource/mcp"`,
    );
    expect(body).toEqual({ error: "unauthorized" });
  });

  it("refuses service tokens with 403", async () => {
    const svc = userClaims({ common_name: "client.access", sub: "" });
    delete svc.email;
    expect((await send(mcpRequest(rpc("tools/list"), { token: await issuer.sign(svc) }))).res.status).toBe(403);
  });

  it("enforces the Host header", async () => {
    const { res } = await send(mcpRequest(rpc("tools/list"), { token, url: "https://evil.example.net/mcp" }));
    expect(res.status).toBe(421);
  });

  it("refuses any Origin not in the allowlist", async () => {
    const { res } = await send(mcpRequest(rpc("tools/list"), { token, headers: { origin: "https://evil.example" } }));
    expect(res.status).toBe(403);
    const env = makeEnv({ overrides: { ALLOWED_ORIGINS: "https://ok.example" } });
    expect((await send(mcpRequest(rpc("ping"), { token, headers: { origin: "https://ok.example" } }), env)).res.status).toBe(200);
  });

  it("applies the optional email allowlist and the header/JWT email match", async () => {
    const env = makeEnv({ overrides: { ALLOWED_EMAILS: "bob@example.com" } });
    expect((await send(mcpRequest(rpc("ping"), { token }), env)).res.status).toBe(403);
    const env2 = makeEnv({ overrides: { ALLOWED_EMAIL_DOMAINS: "example.com" } });
    expect((await send(mcpRequest(rpc("ping"), { token }), env2)).res.status).toBe(200);
    const mismatch = mcpRequest(rpc("ping"), { token, headers: { "cf-access-authenticated-user-email": "bob@example.com" } });
    expect((await send(mismatch)).res.status).toBe(403);
  });

  it("sets security headers and no CORS", async () => {
    const { res } = await send(mcpRequest(rpc("ping"), { token }));
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("strict-transport-security")).toContain("max-age=");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("fails closed with 503 on missing or bad configuration", async () => {
    for (const overrides of [{ CF_ACCESS_AUD: "" }, { BROKER_MODE: "direct" }, { CF_ACCESS_TEAM_DOMAIN: "http://x.cloudflareaccess.com" }, { BROKER: undefined }, { IDENTITY_SIGNING_KEY: "" }]) {
      const { res } = await send(mcpRequest(rpc("ping"), { token }), makeEnv({ overrides }));
      expect(res.status).toBe(503);
    }
    const access = makeEnv({ overrides: { BROKER_MODE: "access", BROKER_URL: "http://broker.example.com" } });
    expect((await send(mcpRequest(rpc("ping"), { token }), access)).res.status).toBe(503);
  });

  it("default export turns unexpected exceptions into a bare 500", async () => {
    const boom = () => {
      throw new Error("secret detail");
    };
    const env = makeEnv({ overrides: { AUDIT_CHAIN: { idFromName: boom, get: boom } } });
    const res = await worker.fetch(mcpRequest(rpc("ping"), { token }), env, ctx);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("secret detail");
  });
});

describe("JSON-RPC guard", () => {
  it("rejects batches", async () => {
    const { res, body } = await send(mcpRequest([rpc("ping"), rpc("ping")], { token }));
    expect(res.status).toBe(400);
    expect(body.error.code).toBe(-32600);
  });

  it("rejects non-objects, wrong jsonrpc and responses", async () => {
    expect((await send(mcpRequest("x", { token }))).body.error.code).toBe(-32600);
    expect((await send(mcpRequest({ jsonrpc: "1.0", id: 1, method: "ping" }, { token }))).body.error.code).toBe(-32600);
    expect((await send(mcpRequest({ jsonrpc: "2.0", id: 1, result: {} }, { token }))).body.error.code).toBe(-32600);
  });

  it("rejects invalid JSON with a parse error", async () => {
    const { res, body } = await send(mcpRequest(null, { token, rawBody: "{nope" }));
    expect(res.status).toBe(400);
    expect(body.error.code).toBe(-32700);
  });

  it("enforces the method allowlist", async () => {
    const { res, body } = await send(mcpRequest(rpc("resources/list"), { token }));
    expect(res.status).toBe(200); // legacy era: 200 + error (a 404 means "session gone" to 2025 clients)
    expect(body.error.code).toBe(-32601);
    const modern = await send(mcpRequest(rpc("resources/list", { _meta: MODERN_META }), { token, headers: modernHeaders("resources/list") }));
    expect(modern.res.status).toBe(404);
    expect(modern.body.error.code).toBe(-32601);
  });

  it("accepts allowed notifications with 202 and refuses others", async () => {
    expect((await send(mcpRequest({ jsonrpc: "2.0", method: "notifications/initialized" }, { token }))).res.status).toBe(202);
    expect((await send(mcpRequest({ jsonrpc: "2.0", method: "notifications/roots/list_changed" }, { token }))).res.status).toBe(400);
    expect((await send(mcpRequest({ jsonrpc: "2.0", method: "tools/list" }, { token }))).res.status).toBe(400);
  });

  it("caps the body by Content-Length and by actual bytes", async () => {
    const big = JSON.stringify({ ...rpc("ping"), pad: "x".repeat(MAX_REQUEST_BYTES) });
    const declared = mcpRequest(null, { token, rawBody: big, headers: { "content-length": String(big.length) } });
    expect((await send(declared)).res.status).toBe(413);
    // No Content-Length (streamed body): the actual byte count is enforced.
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode(big));
        c.close();
      },
    });
    const req = new Request(`https://${HOST}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", "cf-access-jwt-assertion": token },
      body: stream,
      // @ts-expect-error Node fetch needs duplex for stream bodies
      duplex: "half",
    });
    expect(req.headers.get("content-length")).toBeNull();
    expect((await send(req)).res.status).toBe(413);
  });

  it("requires application/json", async () => {
    expect((await send(mcpRequest(rpc("ping"), { token, headers: { "content-type": "text/plain" } }))).res.status).toBe(415);
  });
});

describe("protocol versions", () => {
  it("negotiates initialize for each legacy version and falls back to the latest legacy", async () => {
    for (const v of ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]) {
      const { body } = await send(mcpRequest(rpc("initialize", { protocolVersion: v, capabilities: {}, clientInfo: { name: "t", version: "1" } }), { token }));
      expect(body.result.protocolVersion).toBe(v);
      expect(body.result.capabilities).toEqual({ tools: { listChanged: false } });
      expect(body.result.serverInfo.name).toBe("proxmox-mcp");
    }
    const { body } = await send(mcpRequest(rpc("initialize", { protocolVersion: "1999-01-01", capabilities: {} }), { token }));
    expect(body.result.protocolVersion).toBe("2025-11-25");
  });

  it("legacy: rejects an unknown MCP-Protocol-Version header", async () => {
    const { res, body } = await send(mcpRequest(rpc("tools/list"), { token, headers: { "mcp-protocol-version": "2030-01-01" } }));
    expect(res.status).toBe(400);
    expect(body.error.code).toBe(-32022);
    expect(body.error.data.supported).toContain("2025-06-18");
  });

  it("modern 2026-07-28: requires matching headers", async () => {
    const ok = await send(mcpRequest(rpc("tools/list", { _meta: MODERN_META }), { token, headers: modernHeaders("tools/list") }));
    expect(ok.res.status).toBe(200);
    expect(ok.body.result.resultType).toBe("complete");
    expect(ok.body.result.cacheScope).toBe("public");
    expect(typeof ok.body.result.ttlMs).toBe("number");
    expect(ok.body.result._meta["io.modelcontextprotocol/serverInfo"].name).toBe("proxmox-mcp");

    const noHeader = await send(mcpRequest(rpc("tools/list", { _meta: MODERN_META }), { token, headers: { "mcp-method": "tools/list" } }));
    expect(noHeader.res.status).toBe(400);
    expect(noHeader.body.error.code).toBe(-32020);

    const wrongMethod = await send(mcpRequest(rpc("tools/list", { _meta: MODERN_META }), { token, headers: modernHeaders("tools/call") }));
    expect(wrongMethod.body.error.code).toBe(-32020);

    const headerOnly = await send(mcpRequest(rpc("tools/list"), { token, headers: modernHeaders("tools/list") }));
    expect(headerOnly.body.error.code).toBe(-32020);
  });

  it("modern: unsupported version -> -32022 with supported list", async () => {
    const meta = { ...MODERN_META, "io.modelcontextprotocol/protocolVersion": "2031-01-01" };
    const { res, body } = await send(
      mcpRequest(rpc("tools/list", { _meta: meta }), { token, headers: { ...modernHeaders("tools/list"), "mcp-protocol-version": "2031-01-01" } }),
    );
    expect(res.status).toBe(400);
    expect(body.error.code).toBe(-32022);
    expect(body.error.data).toEqual({ supported: ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"], requested: "2031-01-01" });
  });

  it("modern: Mcp-Name must match the tool name (base64 sentinel decoded)", async () => {
    const call = { ...callTool("list_tools", { search_terms: ["vm"] }) };
    (call.params as Record<string, unknown>)._meta = MODERN_META;
    const bad = await send(mcpRequest(call, { token, headers: modernHeaders("tools/call", "execute_tool") }));
    expect(bad.body.error.code).toBe(-32020);
    const sentinel = `=?base64?${btoa("list_tools")}?=`;
    const good = await send(mcpRequest(call, { token, headers: modernHeaders("tools/call", sentinel) }));
    expect(good.res.status).toBe(200);
    expect(good.body.result.resultType).toBe("complete");
  });

  it("modern: server/discover advertises all versions; ping is removed", async () => {
    const d = await send(mcpRequest(rpc("server/discover", { _meta: MODERN_META }), { token, headers: modernHeaders("server/discover") }));
    expect(d.body.result.supportedVersions[0]).toBe("2026-07-28");
    expect(d.body.result.capabilities).toEqual({ tools: {} });
    const p = await send(mcpRequest(rpc("ping", { _meta: MODERN_META }), { token, headers: modernHeaders("ping") }));
    expect(p.res.status).toBe(404);
  });
});

describe("tools/list and direct calls", () => {
  it("lists exactly the three meta-tools with STD-02 annotations", async () => {
    const { body } = await send(mcpRequest(rpc("tools/list"), { token }));
    const tools = body.result.tools as { name: string; annotations: Record<string, boolean> }[];
    expect(tools.map((t) => t.name)).toEqual(["list_tools", "describe_tool_input", "execute_tool"]);
    expect(tools[0]!.annotations).toMatchObject({ readOnlyHint: true, idempotentHint: true });
    expect(tools[1]!.annotations).toMatchObject({ readOnlyHint: true, idempotentHint: true });
    expect(tools[2]!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true, openWorldHint: true });
  });

  it("calling an operation name directly is a protocol error", async () => {
    const { body } = await send(mcpRequest(callTool("get_vm_status", {}), { token }));
    expect(body.error.code).toBe(-32602);
    expect(body.error.message).toBe("Unknown tool: get_vm_status");
  });
});

describe("rate limits", () => {
  it("per-minute limit -> 429 before the body is read", async () => {
    const env = makeEnv({ minuteAllowed: () => false });
    const { res, body } = await send(mcpRequest(rpc("ping"), { token }), env);
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    expect(body.error.code).toBe(-32000);
  });

  it("daily cap counts tools/call per user", async () => {
    const env = makeEnv({ dailyLimit: 2 });
    const call = () => send(mcpRequest(callTool("list_tools", { search_terms: ["vm"] }), { token }), env);
    expect((await call()).res.status).toBe(200);
    expect((await call()).res.status).toBe(200);
    const third = await call();
    expect(third.res.status).toBe(429);
    expect(third.body.error.message).toBe("daily quota exceeded");
    // Another user has their own counter.
    const bob = await issuer.sign(userClaims({ email: "bob@example.com" }));
    expect((await send(mcpRequest(callTool("list_tools", { search_terms: ["vm"] }), { token: bob }), env)).res.status).toBe(200);
  });
});

describe("audit lines", () => {
  it("logs one JSON line per request without argument values", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await send(mcpRequest(callTool("execute_tool", { name: "get_vm_status", arguments: { node: "pve-secret-node", vmid: 101 } }), { token }));
      const lines = log.mock.calls.map((c) => JSON.parse(String(c[0])) as Record<string, unknown>);
      const rec = lines.find((l) => l.event === "request")!;
      expect(rec).toMatchObject({ user: "alice@example.com", rpc: "tools/call", tool: "execute_tool", target: "get_vm_status", arg_keys: ["node", "vmid"], broker_status: 200, status: 200, is_error: false });
      expect(rec.args_sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(rec.broker_jti).toMatch(/^[0-9a-f-]{36}$/);
      expect(rec.ray).toBe("8f0000000000abcd-EWR");
      expect(JSON.stringify(lines)).not.toContain("pve-secret-node");
      expect(JSON.stringify(lines)).not.toContain(token);
    } finally {
      log.mockRestore();
    }
  });

  it("logs denials with a reason", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await send(mcpRequest(rpc("ping")));
      const rec = JSON.parse(String(log.mock.calls[0]![0]));
      expect(rec).toMatchObject({ event: "denied", deny: "missing token", status: 401 });
    } finally {
      log.mockRestore();
    }
  });
});
