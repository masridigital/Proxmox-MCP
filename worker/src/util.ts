// Small helpers shared by the Worker modules. WebCrypto and TextEncoder only.

const enc = new TextEncoder();

export function utf8(s: string): Uint8Array {
  return enc.encode(s);
}

export function b64urlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? utf8(data) : data;
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

/** Strict base64url decode (no padding, no other alphabet). Throws on bad input. */
export function b64urlDecode(s: string): Uint8Array {
  if (!B64URL_RE.test(s) || s.length % 4 === 1) throw new Error("bad base64url");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hex(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}

/** JSON with object keys sorted recursively, so equal values hash equally. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeys((value as Record<string, unknown>)[k]);
    return out;
  }
  return value;
}

export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Comma-separated env list -> trimmed, non-empty entries. */
export function csv(value: string | undefined, lower = false): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => (lower ? s.trim().toLowerCase() : s.trim()))
    .filter(Boolean);
}

/** Read a body stream up to `cap` bytes. Returns null if the body is larger. */
export async function readCapped(body: ReadableStream<Uint8Array> | null, cap: number): Promise<Uint8Array | null> {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/** Remove control characters and cap length; for short messages that reach the model. */
export function cleanText(s: string, max = 300): string {
  // eslint-disable-next-line no-control-regex
  const t = s.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, " ");
  return t.length > max ? `${t.slice(0, max)}...` : t;
}

const strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

/** Strict UTF-8 decode: invalid byte sequences throw instead of becoming U+FFFD. */
export function decodeUtf8(bytes: Uint8Array): string {
  return strictDecoder.decode(bytes);
}
