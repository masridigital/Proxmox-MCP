// Calls to the on-prem broker. Two transports:
//   vpc    -> env.BROKER (Workers VPC Service binding over the broker's Cloudflare Tunnel)
//   access -> public fetch to the broker hostname, Access service token headers
// Every call carries a fresh X-MCP-Identity assertion bound to method, path and body bytes.
// Redirects are never followed, the call times out, and the response is size-capped and
// parsed defensively. The broker's response bodies are never echoed beyond its `text`.

import type { Config, Env } from "./config";
import { signAssertion } from "./assertion";
import { decodeUtf8, isPlainObject, readCapped, utf8 } from "./util";

export const BROKER_TIMEOUT_MS = 25_000;
export const MAX_BROKER_BYTES = 2 * 1024 * 1024;

export class BrokerError extends Error {
  constructor(
    message: string,
    public status: number, // HTTP status from the broker, 0 = transport failure
  ) {
    super(message);
  }
}

const STATUS_MESSAGES: Record<number, string> = {
  400: "the broker rejected the request as malformed",
  401: "the broker did not accept this Worker's credentials",
  403: "you are not enrolled on the Proxmox broker",
  404: "broker endpoint not found",
  413: "request too large for the broker",
  429: "broker rate limit reached; retry later",
  503: "the Proxmox broker is temporarily unavailable",
};

export interface BrokerCallInfo {
  status: number;
  jti: string;
  bytes: number;
}

export interface BrokerContext {
  env: Env;
  config: Config;
  user: string;
  ray: string;
}

async function call(ctx: BrokerContext, method: "GET" | "POST", path: string, body: Uint8Array, info: BrokerCallInfo): Promise<unknown> {
  const { env, config } = ctx;
  const { jws, claims } = await signAssertion({
    pem: env.IDENTITY_SIGNING_KEY,
    kid: config.keyId,
    sub: ctx.user,
    method,
    path,
    body,
    ray: ctx.ray,
  });
  info.jti = claims.jti;
  const headers: Record<string, string> = { accept: "application/json", "x-mcp-identity": jws };
  if (method === "POST") headers["content-type"] = "application/json";
  if (config.brokerMode === "access") {
    headers["cf-access-client-id"] = env.BROKER_ACCESS_CLIENT_ID!;
    headers["cf-access-client-secret"] = env.BROKER_ACCESS_CLIENT_SECRET!;
  }
  const init: RequestInit = {
    method,
    headers,
    body: method === "POST" ? body : undefined,
    redirect: "manual",
    signal: AbortSignal.timeout(BROKER_TIMEOUT_MS),
  };
  const url = `${config.brokerBase}${path}`;
  let res: Response;
  try {
    res = config.brokerMode === "vpc" ? await env.BROKER!.fetch(url, init) : await fetch(url, init);
  } catch (e) {
    const timeout = e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError");
    throw new BrokerError(timeout ? "the Proxmox broker timed out" : "the Proxmox broker is unreachable", 0);
  }
  info.status = res.status;
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > MAX_BROKER_BYTES) {
    await res.body?.cancel().catch(() => undefined);
    throw new BrokerError("broker response too large", res.status);
  }
  if (res.status !== 200) {
    await res.body?.cancel().catch(() => undefined);
    throw new BrokerError(STATUS_MESSAGES[res.status] ?? `broker error (HTTP ${res.status})`, res.status);
  }
  let raw: Uint8Array | null;
  try {
    raw = await readCapped(res.body, MAX_BROKER_BYTES);
  } catch {
    throw new BrokerError("the Proxmox broker timed out", res.status);
  }
  if (raw === null) throw new BrokerError("broker response too large", res.status);
  info.bytes = raw.byteLength;
  try {
    return JSON.parse(decodeUtf8(raw));
  } catch {
    throw new BrokerError("broker returned an invalid response", res.status);
  }
}

export interface CatalogTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  tier: string;
}

export interface Catalog {
  version: string;
  tools: CatalogTool[];
}

export const TOOL_NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_TOOLS = 2000;
const MAX_DESCRIPTION = 2000;

export function parseCatalog(doc: unknown): Catalog {
  if (!isPlainObject(doc) || !Array.isArray(doc.tools)) throw new BrokerError("broker returned an invalid catalog", 200);
  const seen = new Set<string>();
  const tools: CatalogTool[] = [];
  for (const t of doc.tools.slice(0, MAX_TOOLS)) {
    if (!isPlainObject(t) || typeof t.name !== "string" || !TOOL_NAME_RE.test(t.name) || seen.has(t.name)) continue;
    if (typeof t.description !== "string" || !isPlainObject(t.inputSchema) || typeof t.tier !== "string") continue;
    if (t.tier === "forbidden") continue; // never shown, even if a broker bug lists it
    seen.add(t.name);
    tools.push({
      name: t.name,
      description: t.description.slice(0, MAX_DESCRIPTION),
      inputSchema: t.inputSchema,
      tier: t.tier,
    });
  }
  return { version: typeof doc.version === "string" ? doc.version.slice(0, 128) : "", tools };
}

export async function fetchCatalog(ctx: BrokerContext, info: BrokerCallInfo): Promise<Catalog> {
  return parseCatalog(await call(ctx, "GET", "/v1/catalog", new Uint8Array(0), info));
}

export interface ExecuteResult {
  ok: boolean;
  text: string;
}

export async function executeTool(ctx: BrokerContext, tool: string, args: Record<string, unknown>, info: BrokerCallInfo): Promise<ExecuteResult> {
  const body = utf8(JSON.stringify({ tool, arguments: args }));
  const doc = await call(ctx, "POST", "/v1/execute", body, info);
  if (!isPlainObject(doc) || typeof doc.ok !== "boolean" || typeof doc.text !== "string") {
    throw new BrokerError("broker returned an invalid response", info.status);
  }
  return { ok: doc.ok, text: doc.text };
}
