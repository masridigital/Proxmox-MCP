// JSON-RPC 2.0 guard and MCP protocol version handling for Streamable HTTP (stateless JSON).
//
// Dual-era server (MCP 2026-07-28 "Versioning: Backward Compatibility"):
//   legacy  2024-11-05 .. 2025-11-25: initialize handshake; MCP-Protocol-Version header
//           optional (absent = 2025-03-26) and, when present, must be a legacy version.
//   modern  2026-07-28: no handshake; every request carries
//           params._meta["io.modelcontextprotocol/protocolVersion"], which must equal the
//           MCP-Protocol-Version header, plus Mcp-Method (and Mcp-Name for tools/call).
// No sessions are minted; Mcp-Session-Id and Last-Event-ID are ignored.

import { decodeUtf8, isPlainObject } from "./util";

export const MODERN_VERSIONS = ["2026-07-28"] as const;
export const LEGACY_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"] as const;
export const SUPPORTED_VERSIONS: string[] = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];
export const DEFAULT_LEGACY_VERSION = "2025-03-26";

export const META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion";

export const PARSE_ERROR = -32700;
export const INVALID_REQUEST = -32600;
export const METHOD_NOT_FOUND = -32601;
export const INVALID_PARAMS = -32602;
export const SERVER_ERROR = -32000; // implementation-defined: rate limit, quota
export const HEADER_MISMATCH = -32020;
export const UNSUPPORTED_PROTOCOL_VERSION = -32022;

const REQUEST_METHODS = new Set(["initialize", "ping", "tools/list", "tools/call", "server/discover"]);
const NOTIFICATION_METHODS = new Set(["notifications/initialized", "notifications/cancelled"]);

export type RpcId = string | number | null;

/** Method name for the audit log: allowlisted names verbatim, anything else "other" (a
 *  free-form method string is caller-controlled text and could carry PHI). */
export function auditMethodName(method: string): string {
  return REQUEST_METHODS.has(method) || NOTIFICATION_METHODS.has(method) ? method : "other";
}

export class RpcError extends Error {
  constructor(
    public code: number,
    message: string,
    public httpStatus = 200,
    public data?: unknown,
  ) {
    super(message);
  }
}

export interface RpcMessage {
  id: RpcId;
  isNotification: boolean;
  method: string;
  params: Record<string, unknown>;
  era: "legacy" | "modern";
  version: string; // negotiated or requested version
}

/** Validate shape and method allowlist. `body` is the parsed JSON. */
export function parseMessage(body: unknown): { id: RpcId; isNotification: boolean; method: string; params: Record<string, unknown> } {
  if (Array.isArray(body)) throw new RpcError(INVALID_REQUEST, "batch requests are not supported", 400);
  if (!isPlainObject(body)) throw new RpcError(INVALID_REQUEST, "request must be a JSON object", 400);
  if (body.jsonrpc !== "2.0") throw new RpcError(INVALID_REQUEST, "jsonrpc must be \"2.0\"", 400);
  if ("result" in body || "error" in body) throw new RpcError(INVALID_REQUEST, "responses are not accepted", 400);
  const hasId = "id" in body;
  const id = body.id;
  if (hasId && !((typeof id === "string" && id.length <= 128) || (typeof id === "number" && Number.isSafeInteger(id)))) {
    throw new RpcError(INVALID_REQUEST, "id must be a string or integer", 400);
  }
  if (typeof body.method !== "string" || body.method.length > 64) throw new RpcError(INVALID_REQUEST, "method must be a string", 400, undefined);
  if (body.params !== undefined && !isPlainObject(body.params)) throw new RpcError(INVALID_REQUEST, "params must be an object", 400);
  const method = body.method;
  const params = (body.params ?? {}) as Record<string, unknown>;
  const rid = hasId ? (id as RpcId) : null;
  if (!hasId) {
    if (!NOTIFICATION_METHODS.has(method)) {
      throw new RpcError(method.startsWith("notifications/") ? METHOD_NOT_FOUND : INVALID_REQUEST, "method not allowed", 400);
    }
    return { id: null, isNotification: true, method, params };
  }
  return { id: rid, isNotification: false, method, params };
}

/** Method allowlist, after negotiation: modern answers 404, legacy 200 (a legacy 404 means
 *  "session expired" to 2025-era clients and would make them re-initialize in a loop). */
export function checkMethod(msg: RpcMessage): void {
  const ok = REQUEST_METHODS.has(msg.method) && !(msg.era === "modern" && msg.method === "ping");
  if (!ok) throw new RpcError(METHOD_NOT_FOUND, "method not allowed", msg.era === "modern" ? 404 : 200);
}

/** Decode an Mcp-Name / Mcp-Param value (plain or =?base64?...?= sentinel). */
export function decodeHeaderValue(value: string): string | null {
  const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(value);
  if (!m) return value;
  try {
    const bin = atob(m[1]!);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return decodeUtf8(bytes);
  } catch {
    return null;
  }
}

/** Decide the protocol era and version, enforcing the header rules of each era. */
export function negotiate(msg: ReturnType<typeof parseMessage>, headers: Headers): RpcMessage {
  const header = headers.get("mcp-protocol-version");
  const meta = isPlainObject(msg.params._meta) ? msg.params._meta : undefined;
  const metaVersion = meta?.[META_VERSION_KEY];

  if (msg.method === "initialize") {
    const requested = msg.params.protocolVersion;
    if (typeof requested !== "string") throw new RpcError(INVALID_PARAMS, "protocolVersion is required", 400);
    const version = (LEGACY_VERSIONS as readonly string[]).includes(requested) ? requested : LEGACY_VERSIONS[0];
    return { ...msg, era: "legacy", version };
  }

  if (metaVersion !== undefined) {
    if (typeof metaVersion !== "string") throw new RpcError(INVALID_PARAMS, "_meta protocolVersion must be a string", 400);
    if (header === null) throw new RpcError(HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version header is required", 400);
    if (header !== metaVersion) throw new RpcError(HEADER_MISMATCH, "Header mismatch: MCP-Protocol-Version does not match _meta", 400);
    if (!(MODERN_VERSIONS as readonly string[]).includes(metaVersion)) {
      throw new RpcError(UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version", 400, {
        supported: SUPPORTED_VERSIONS,
        requested: metaVersion.slice(0, 32),
      });
    }
    if (!msg.isNotification) {
      if (headers.get("mcp-method") !== msg.method) throw new RpcError(HEADER_MISMATCH, "Header mismatch: Mcp-Method", 400);
      if (msg.method === "tools/call") {
        const raw = headers.get("mcp-name");
        if (raw === null || decodeHeaderValue(raw) !== msg.params.name) throw new RpcError(HEADER_MISMATCH, "Header mismatch: Mcp-Name", 400);
      }
    }
    return { ...msg, era: "modern", version: metaVersion };
  }

  // Legacy request without _meta.
  if (header !== null) {
    if ((MODERN_VERSIONS as readonly string[]).includes(header)) {
      throw new RpcError(HEADER_MISMATCH, "Header mismatch: _meta protocolVersion is required", 400);
    }
    if (!(LEGACY_VERSIONS as readonly string[]).includes(header)) {
      throw new RpcError(UNSUPPORTED_PROTOCOL_VERSION, "Unsupported protocol version", 400, {
        supported: SUPPORTED_VERSIONS,
        requested: header.slice(0, 32),
      });
    }
  }
  return { ...msg, era: "legacy", version: header ?? DEFAULT_LEGACY_VERSION };
}
