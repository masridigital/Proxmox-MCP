// Test helpers: a fake Cloudflare Access issuer (RSA JWKS), a fake broker that verifies the
// X-MCP-Identity assertion exactly like the Python broker, and in-memory bindings.
import vector from "./fixtures/assertion-vector.json";
import type { Env } from "../src/config";
import { DailyQuota } from "../src/quota";
import { b64urlDecode, b64urlEncode, sha256Hex, utf8 } from "../src/util";

export const TEAM = "https://example-team.cloudflareaccess.com";
export const AUD = "a".repeat(64);
export const HOST = "mcp.example.com";
export const BROKER_URL_ACCESS = "https://broker.example.com";

// ------------------------------------------------------------------ Access issuer

export interface Issuer {
  kid: string;
  privateKey: CryptoKey;
  jwks: { keys: JsonWebKey[] };
  sign(claims: Record<string, unknown>, header?: Record<string, unknown>): Promise<string>;
}

export async function makeIssuer(kid = "kid-1"): Promise<Issuer> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return {
    kid,
    privateKey: pair.privateKey,
    jwks: { keys: [{ kty: "RSA", n: jwk.n, e: jwk.e, kid, alg: "RS256", use: "sig" } as JsonWebKey] },
    async sign(claims, header = {}) {
      const h = b64urlEncode(JSON.stringify({ alg: "RS256", kid, typ: "JWT", ...header }));
      const p = b64urlEncode(JSON.stringify(claims));
      const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, utf8(`${h}.${p}`)));
      return `${h}.${p}.${b64urlEncode(sig)}`;
    },
  };
}

export function userClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: TEAM,
    aud: [AUD],
    sub: "0f2a6c1e-0000-4000-8000-000000000abc",
    email: "Alice@Example.com",
    iat: now - 5,
    nbf: now - 5,
    exp: now + 600,
    type: "app",
    ...over,
  };
}

// ------------------------------------------------------------------ fake broker

export interface BrokerCall {
  method: string;
  path: string;
  claims: Record<string, unknown>;
  body: string;
  headers: Headers;
}

export interface CatalogToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  tier: string;
}

export const CATALOG: CatalogToolDef[] = [
  { name: "list_vms", description: "List virtual machines on a node", inputSchema: { type: "object", properties: { node: { type: "string" } } }, tier: "read" },
  { name: "get_vm_status", description: "Get VM status", inputSchema: { type: "object", properties: { node: { type: "string" }, vmid: { type: "integer" } }, required: ["node", "vmid"] }, tier: "read" },
  { name: "list_vm_snapshots", description: "List snapshots of a VM", inputSchema: { type: "object" }, tier: "read" },
  { name: "get_node_status", description: "Node status", inputSchema: { type: "object", properties: { node: { type: "string" } } }, tier: "read" },
  { name: "list_storage", description: "List storage", inputSchema: { type: "object" }, tier: "read" },
];

export type BrokerHandler = (call: BrokerCall) => Response | Promise<Response>;

let publicKey: Promise<CryptoKey> | null = null;
function brokerPublicKey(): Promise<CryptoKey> {
  publicKey ??= crypto.subtle.importKey("raw", b64urlDecode(vector.public_key_raw_b64url), { name: "Ed25519" }, false, ["verify"]);
  return publicKey;
}

/** Verify X-MCP-Identity like the Python broker does; throws on any mismatch. */
export async function verifyIdentity(jws: string, body: Uint8Array, method: string, path: string): Promise<Record<string, unknown>> {
  const [h, p, s] = jws.split(".");
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(h!))) as Record<string, unknown>;
  if (header.alg !== "EdDSA") throw new Error("alg");
  const ok = await crypto.subtle.verify({ name: "Ed25519" }, await brokerPublicKey(), b64urlDecode(s!), utf8(`${h}.${p}`));
  if (!ok) throw new Error("signature");
  const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(p!))) as Record<string, unknown>;
  if (claims.iss !== "proxmox-mcp-worker" || claims.aud !== "proxmox-broker") throw new Error("iss/aud");
  if ((claims.exp as number) - (claims.iat as number) !== 60) throw new Error("lifetime");
  if (claims.req !== (await sha256Hex(body))) throw new Error("req");
  if (claims.method !== method || claims.path !== path) throw new Error("method/path");
  return claims;
}

export function defaultBroker(calls: BrokerCall[], catalog: CatalogToolDef[] = CATALOG): BrokerHandler {
  return (call) => {
    calls.push(call);
    if (call.method === "GET" && call.path === "/v1/catalog") {
      return Response.json({ mode: "ro", version: "v-test", tools: catalog });
    }
    if (call.method === "POST" && call.path === "/v1/execute") {
      const req = JSON.parse(call.body) as { tool: string; arguments: Record<string, unknown> };
      return Response.json({ ok: true, text: JSON.stringify({ tool: req.tool, data: { status: "running" } }) });
    }
    return new Response("not found", { status: 404 });
  };
}

async function runBroker(handler: BrokerHandler, input: string | Request, init?: RequestInit): Promise<Response> {
  const req = new Request(input, init);
  const body = new Uint8Array(await req.arrayBuffer());
  const url = new URL(req.url);
  const jws = req.headers.get("x-mcp-identity") ?? "";
  if (req.headers.get("origin")) return new Response(null, { status: 403 });
  let claims: Record<string, unknown>;
  try {
    claims = await verifyIdentity(jws, body, req.method, url.pathname);
  } catch {
    return Response.json({ error: "unauthorized" }, { status: 401 });
  }
  return handler({ method: req.method, path: url.pathname, claims, body: new TextDecoder().decode(body), headers: req.headers });
}

// ------------------------------------------------------------------ env + fetch

function memoryStorage() {
  const m = new Map<string, unknown>();
  let alarm: number | null = null;
  return {
    map: m,
    async get<T>(k: string) {
      return m.get(k) as T | undefined;
    },
    async put(k: string | Record<string, unknown>, v?: unknown) {
      if (typeof k === "string") m.set(k, structuredClone(v));
      else for (const [kk, vv] of Object.entries(k)) m.set(kk, structuredClone(vv));
    },
    async delete(keys: string[]) {
      let n = 0;
      for (const k of keys) if (m.delete(k)) n++;
      return n;
    },
    async list<T>({ prefix, limit }: { prefix: string; limit?: number }) {
      const out = new Map<string, T>();
      for (const k of [...m.keys()].sort()) {
        if (k.startsWith(prefix)) out.set(k, m.get(k) as T);
        if (limit && out.size >= limit) break;
      }
      return out;
    },
    async getAlarm() {
      return alarm;
    },
    async setAlarm(t: number) {
      alarm = t;
    },
  };
}

export function memoryState() {
  const storage = memoryStorage();
  let chain = Promise.resolve();
  return {
    storage,
    blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T> {
      const run = chain.then(fn);
      chain = run.then(
        () => undefined,
        () => undefined,
      );
      return run;
    },
  };
}

export interface TestEnvOptions {
  broker?: BrokerHandler;
  minuteAllowed?: () => boolean;
  dailyLimit?: number;
  overrides?: Partial<Env>;
}

export function makeEnv(opts: TestEnvOptions = {}): Env {
  const quotas = new Map<string, DailyQuota>();
  const broker = opts.broker ?? defaultBroker([]);
  return {
    CF_ACCESS_TEAM_DOMAIN: TEAM,
    CF_ACCESS_AUD: AUD,
    WORKER_HOSTNAME: HOST,
    BROKER_MODE: "vpc",
    BROKER_URL: "http://broker.internal",
    IDENTITY_KEY_ID: vector.kid,
    IDENTITY_SIGNING_KEY: vector.private_key_pkcs8_pem,
    RATE_PER_DAY: String(opts.dailyLimit ?? 2000),
    BROKER: { fetch: (input, init) => runBroker(broker, input, init) },
    RATE_LIMITER: { limit: async () => ({ success: opts.minuteAllowed ? opts.minuteAllowed() : true }) },
    DAILY_QUOTA: {
      idFromName: (name: string) => name,
      get: (id: unknown) => {
        const key = String(id);
        if (!quotas.has(key)) quotas.set(key, new DailyQuota(memoryState()));
        const obj = quotas.get(key)!;
        return { fetch: (input: string | Request, init?: RequestInit) => obj.fetch(new Request(input, init)) };
      },
    },
    ...opts.overrides,
  };
}

/** Route global fetch: Access certs -> issuer JWKS; access-mode broker URL -> broker handler. */
export function installFetch(issuer: Issuer, broker?: BrokerHandler, counter?: { certs: number }) {
  globalThis.fetch = (async (input: string | Request | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === `${TEAM}/cdn-cgi/access/certs`) {
      if (counter) counter.certs++;
      return Response.json(issuer.jwks);
    }
    if (broker && url.startsWith(BROKER_URL_ACCESS)) return runBroker(broker, url, init);
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
}

export const ctx = { waitUntil: (_p: Promise<unknown>) => undefined };

let nextId = 1;

export interface McpOptions {
  token?: string | null;
  headers?: Record<string, string>;
  method?: string;
  rawBody?: string;
  url?: string;
}

export function mcpRequest(body: unknown, o: McpOptions = {}): Request {
  const headers = new Headers({ "content-type": "application/json", accept: "application/json, text/event-stream", "cf-ray": "8f0000000000abcd-EWR" });
  if (o.token) headers.set("cf-access-jwt-assertion", o.token);
  for (const [k, v] of Object.entries(o.headers ?? {})) headers.set(k, v);
  const method = o.method ?? "POST";
  return new Request(o.url ?? `https://${HOST}/mcp`, {
    method,
    headers,
    body: method === "POST" ? (o.rawBody ?? JSON.stringify(body)) : undefined,
  });
}

export function rpc(method: string, params?: Record<string, unknown>) {
  return { jsonrpc: "2.0", id: nextId++, method, ...(params ? { params } : {}) };
}

export function callTool(name: string, args?: unknown) {
  return rpc("tools/call", { name, ...(args === undefined ? {} : { arguments: args }) });
}
