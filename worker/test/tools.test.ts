import { beforeEach, describe, expect, it } from "vitest";
import { handle } from "../src/index";
import { resetJwksCache } from "../src/access-jwt";
import { LIST_CAP, resetCatalogCache } from "../src/tools";
import { MAX_BROKER_BYTES } from "../src/broker";
import {
  BROKER_URL_ACCESS,
  type BrokerCall,
  type BrokerHandler,
  CATALOG,
  type Issuer,
  callTool,
  ctx,
  defaultBroker,
  installFetch,
  makeEnv,
  makeIssuer,
  mcpRequest,
  userClaims,
} from "./helpers";

let issuer: Issuer;
let token: string;
// Test-only, format-shaped service token values (not real credentials).
const CLIENT_ID = "0123456789abcdef0123456789abcdef.access";
const CLIENT_SECRET = "f".repeat(64);

beforeEach(async () => {
  resetJwksCache();
  resetCatalogCache();
  issuer = await makeIssuer();
  installFetch(issuer);
  token = await issuer.sign(userClaims());
});

async function tool(name: string, args: unknown, broker: BrokerHandler, tok = token) {
  const res = await handle(mcpRequest(callTool(name, args), { token: tok }), makeEnv({ broker }), ctx);
  expect(res.status).toBe(200);
  const body = (await res.json()) as { result: unknown };
  return body.result as { content: { type: string; text: string }[]; isError: boolean };
}

describe("list_tools", () => {
  it("without terms returns a category summary", async () => {
    const calls: BrokerCall[] = [];
    const r = await tool("list_tools", {}, defaultBroker(calls));
    const doc = JSON.parse(r.content[0]!.text);
    expect(doc.visible_tools).toBe(CATALOG.length);
    expect(doc.categories[0]).toMatchObject({ category: "vm", tools: 2 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.path).toBe("/v1/catalog");
    expect(calls[0]!.claims.sub).toBe("alice@example.com");
    expect(calls[0]!.claims.req).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("matches terms on name and description (OR, case-insensitive)", async () => {
    const r = await tool("list_tools", { search_terms: ["SNAPSHOT", "storage"] }, defaultBroker([]));
    expect(JSON.parse(r.content[0]!.text).map((t: { name: string }) => t.name)).toEqual(["list_vm_snapshots", "list_storage"]);
  });

  it(`caps results at ${LIST_CAP}`, async () => {
    const many = Array.from({ length: 80 }, (_, i) => ({ name: `get_thing_${i}`, description: "thing", inputSchema: { type: "object" }, tier: "read" }));
    const r = await tool("list_tools", { search_terms: ["thing"] }, defaultBroker([], many));
    expect(JSON.parse(r.content[0]!.text)).toHaveLength(LIST_CAP);
    expect(r.content[1]!.text).toContain("80 tools match");
  });

  it("validates input strictly", async () => {
    expect((await tool("list_tools", { search_terms: "vm" }, defaultBroker([]))).isError).toBe(true);
    expect((await tool("list_tools", { other: 1 }, defaultBroker([]))).isError).toBe(true);
    expect((await tool("list_tools", { search_terms: ["a", "b", "c", "d", "e", "f"] }, defaultBroker([]))).isError).toBe(true);
  });

  it("caches the catalog per user for 60 s", async () => {
    const calls: BrokerCall[] = [];
    const broker = defaultBroker(calls);
    const env = makeEnv({ broker });
    const req = (tok: string) => handle(mcpRequest(callTool("list_tools", { search_terms: ["vm"] }), { token: tok }), env, ctx);
    await req(token);
    await req(token);
    expect(calls.filter((c) => c.path === "/v1/catalog")).toHaveLength(1);
    await req(await issuer.sign(userClaims({ email: "bob@example.com" })));
    const catalogCalls = calls.filter((c) => c.path === "/v1/catalog");
    expect(catalogCalls).toHaveLength(2);
    expect(catalogCalls[1]!.claims.sub).toBe("bob@example.com");
  });

  it("drops malformed and forbidden catalog entries", async () => {
    const bad = [
      ...CATALOG.slice(0, 1),
      { name: "bad name!", description: "x", inputSchema: {}, tier: "read" },
      { name: "delete_everything", description: "x", inputSchema: {}, tier: "forbidden" },
      { name: "no_schema", description: "x", tier: "read" },
    ];
    const r = await tool("list_tools", {}, defaultBroker([], bad as never));
    expect(JSON.parse(r.content[0]!.text).visible_tools).toBe(1);
  });
});

describe("describe_tool_input", () => {
  it("returns schema blocks for visible tools", async () => {
    const r = await tool("describe_tool_input", { tool_names: ["get_vm_status", "list_vms"] }, defaultBroker([]));
    expect(r.isError).toBe(false);
    expect(r.content[0]!.text).toContain('<input_schema tool="get_vm_status">');
    expect(r.content[0]!.text).toContain('"required": [');
  });

  it("hidden and nonexistent tools get the same answer", async () => {
    // delete_vm exists on the broker but is not in this user's catalog.
    const hidden = await tool("describe_tool_input", { tool_names: ["delete_vm"] }, defaultBroker([]));
    const missing = await tool("describe_tool_input", { tool_names: ["no_such_tool"] }, defaultBroker([]));
    expect(hidden).toEqual({ content: [{ type: "text", text: "Unknown tool: delete_vm" }], isError: true });
    expect(missing).toEqual({ content: [{ type: "text", text: "Unknown tool: no_such_tool" }], isError: true });
  });

  it("rejects invalid tool names", async () => {
    expect((await tool("describe_tool_input", { tool_names: ["../x"] }, defaultBroker([]))).isError).toBe(true);
    expect((await tool("describe_tool_input", { tool_names: [] }, defaultBroker([]))).isError).toBe(true);
  });
});

describe("execute_tool", () => {
  it("calls the broker with {tool, arguments} and a bound assertion, then labels the result", async () => {
    const calls: BrokerCall[] = [];
    const r = await tool("execute_tool", { name: "get_vm_status", arguments: { node: "pve1", vmid: 101 } }, defaultBroker(calls));
    expect(r.isError).toBe(false);
    const exec = calls.find((c) => c.path === "/v1/execute")!;
    expect(JSON.parse(exec.body)).toEqual({ tool: "get_vm_status", arguments: { node: "pve1", vmid: 101 } });
    expect(Object.keys(JSON.parse(exec.body))).toEqual(["tool", "arguments"]);
    expect(exec.claims).toMatchObject({ method: "POST", path: "/v1/execute", sub: "alice@example.com", ray: "8f0000000000abcd-EWR" });
    expect(exec.headers.get("content-type")).toBe("application/json");
    expect(exec.headers.get("origin")).toBeNull();
    expect(exec.headers.get("cf-access-client-id")).toBeNull(); // vpc mode
    expect(r.content[0]!.text).toMatch(/^UNTRUSTED DATA from the Proxmox API \(tool get_vm_status\)/);
    expect(r.content[0]!.text).toContain('"status": "running"');
  });

  it("defaults missing arguments to {}", async () => {
    const calls: BrokerCall[] = [];
    await tool("execute_tool", { name: "list_storage" }, defaultBroker(calls));
    expect(JSON.parse(calls.find((c) => c.path === "/v1/execute")!.body)).toEqual({ tool: "list_storage", arguments: {} });
  });

  it("does not forward tools outside the caller's catalog", async () => {
    const calls: BrokerCall[] = [];
    const r = await tool("execute_tool", { name: "delete_vm", arguments: {} }, defaultBroker(calls));
    expect(r).toEqual({ content: [{ type: "text", text: "Unknown tool: delete_vm" }], isError: true });
    expect(calls.some((c) => c.path === "/v1/execute")).toBe(false);
  });

  it("broker ok:false becomes an isError result with the broker text", async () => {
    const broker: BrokerHandler = (c) =>
      c.path === "/v1/catalog" ? Response.json({ tools: CATALOG }) : Response.json({ ok: false, text: "get_vm_status: this MCP user is read-only" });
    const r = await tool("execute_tool", { name: "get_vm_status", arguments: {} }, broker);
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).toContain("this MCP user is read-only");
  });

  it("redacts PHI and secrets the broker let through", async () => {
    const broker: BrokerHandler = (c) =>
      c.path === "/v1/catalog"
        ? Response.json({ tools: CATALOG })
        : Response.json({ ok: true, text: '{"description":"pt DOB: 01/02/1980 SSN 123-45-6789","password":"x"}' });
    const text = (await tool("execute_tool", { name: "get_vm_status", arguments: {} }, broker)).content[0]!.text;
    expect(text).not.toMatch(/1980|123-45-6789|"x"/);
  });

  it("maps broker transport failures to short generic errors without echoing bodies", async () => {
    for (const [status, msg] of [
      [401, "did not accept this Worker's credentials"],
      [403, "not enrolled"],
      [429, "rate limit"],
      [503, "temporarily unavailable"],
      [418, "broker error (HTTP 418)"],
    ] as const) {
      resetCatalogCache();
      const broker: BrokerHandler = (c) =>
        c.path === "/v1/catalog" ? Response.json({ tools: CATALOG }) : new Response("Traceback: secret internals", { status });
      const r = await tool("execute_tool", { name: "list_vms", arguments: {} }, broker);
      expect(r.isError).toBe(true);
      expect(r.content[0]!.text).toContain(msg);
      expect(r.content[0]!.text).not.toContain("Traceback");
    }
  });

  it("does not follow redirects", async () => {
    const calls: BrokerCall[] = [];
    const broker: BrokerHandler = (c) => {
      calls.push(c);
      return new Response(null, { status: 302, headers: { location: "https://evil.example/" } });
    };
    const r = await tool("list_tools", {}, broker);
    expect(r.isError).toBe(true);
    expect(r.content[0]!.text).toContain("HTTP 302");
    expect(calls).toHaveLength(1);
  });

  it("refuses oversize broker responses (declared and streamed)", async () => {
    const huge = "x".repeat(MAX_BROKER_BYTES + 1);
    const declared: BrokerHandler = (c) =>
      c.path === "/v1/catalog" ? Response.json({ tools: CATALOG }) : new Response(JSON.stringify({ ok: true, text: huge }), { headers: { "content-length": String(huge.length + 30) } });
    expect((await tool("execute_tool", { name: "list_vms" }, declared)).content[0]!.text).toContain("too large");
    resetCatalogCache();
    const streamed: BrokerHandler = (c) => {
      if (c.path === "/v1/catalog") return Response.json({ tools: CATALOG });
      const enc = new TextEncoder();
      return new Response(
        new ReadableStream({
          start(ctl) {
            ctl.enqueue(enc.encode('{"ok":true,"text":"'));
            ctl.enqueue(enc.encode(huge));
            ctl.enqueue(enc.encode('"}'));
            ctl.close();
          },
        }),
      );
    };
    expect((await tool("execute_tool", { name: "list_vms" }, streamed)).content[0]!.text).toContain("too large");
  });

  it("refuses invalid JSON and wrong shapes from the broker", async () => {
    for (const body of ["not json", '{"ok":"yes","text":1}', "[]"]) {
      resetCatalogCache();
      const broker: BrokerHandler = (c) => (c.path === "/v1/catalog" ? Response.json({ tools: CATALOG }) : new Response(body));
      const r = await tool("execute_tool", { name: "list_vms" }, broker);
      expect(r.isError).toBe(true);
      expect(r.content[0]!.text).toContain("invalid response");
    }
  });

  it("validates execute_tool input", async () => {
    expect((await tool("execute_tool", { name: "list_vms", arguments: [] }, defaultBroker([]))).isError).toBe(true);
    expect((await tool("execute_tool", { name: "list vms" }, defaultBroker([]))).isError).toBe(true);
    expect((await tool("execute_tool", { arguments: {} }, defaultBroker([]))).isError).toBe(true);
    expect((await tool("execute_tool", { name: "list_vms", extra: 1 }, defaultBroker([]))).isError).toBe(true);
    expect((await tool("execute_tool", "x", defaultBroker([]))).isError).toBe(true);
  });

  it("access mode: sends the service token headers to https://<broker-hostname>", async () => {
    const calls: BrokerCall[] = [];
    installFetch(issuer, defaultBroker(calls));
    const env = makeEnv({
      overrides: { BROKER_MODE: "access", BROKER_URL: BROKER_URL_ACCESS, BROKER: undefined, BROKER_ACCESS_CLIENT_ID: CLIENT_ID, BROKER_ACCESS_CLIENT_SECRET: CLIENT_SECRET },
    });
    const res = await handle(mcpRequest(callTool("execute_tool", { name: "list_vms", arguments: {} }), { token }), env, ctx);
    const body = (await res.json()) as { result: { isError: boolean } };
    expect(body.result.isError).toBe(false);
    const exec = calls.find((c) => c.path === "/v1/execute")!;
    expect(exec.headers.get("cf-access-client-id")).toBe(CLIENT_ID);
    expect(exec.headers.get("cf-access-client-secret")).toBe(CLIENT_SECRET);
    expect(JSON.stringify(body)).not.toContain(CLIENT_SECRET);
  });

  it("broker unreachable -> short error", async () => {
    const env = makeEnv({ overrides: { BROKER: { fetch: async () => { throw new TypeError("connect ECONNREFUSED 10.0.0.5"); } } } });
    const res = await handle(mcpRequest(callTool("list_tools", {}), { token }), env, ctx);
    const text = ((await res.json()) as { result: { content: { text: string }[] } }).result.content[0]!.text;
    expect(text).toBe("Proxmox broker error: the Proxmox broker is unreachable");
  });
});
