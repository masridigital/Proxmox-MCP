// Strict JSON (RFC 8259) for bytes that cross a trust boundary.
//
// JSON.parse is lenient in ways that matter at a security gateway:
//   * duplicate keys: last wins, so two parsers in a chain can disagree on "method" or "name";
//   * "__proto__" keys become own properties that later assignment code turns into prototype
//     writes (canonical hashing, object spreads into plain objects);
//   * depth is unbounded, and recursive code downstream (hashing, the broker) overflows;
//   * 1e400 becomes Infinity and 2^64 loses precision, so the broker receives another value;
//   * "\ud800" escapes produce lone surrogates that the Python broker cannot encode.
// This parser rejects all of those. It never builds prototype-bearing keys with assignment
// (properties are defined), so even with forbidKeys off a "__proto__" key stays data.
// With rawNumbers, numbers are kept as their exact source text (RawNumber) so a filter can
// re-serialise broker output without rounding 64-bit integers.

export class JsonError extends Error {
  constructor(
    message: string,
    public kind: "syntax" | "depth" | "duplicate" | "number" | "surrogate" | "forbidden-key" = "syntax",
  ) {
    super(message);
  }
}

export class RawNumber {
  constructor(public readonly raw: string) {}
}

export interface StrictJsonOptions {
  maxDepth: number;
  /** Reject "__proto__", "constructor" and "prototype" keys anywhere. */
  forbidKeys?: boolean;
  /** Keep numbers as RawNumber (exact source text) instead of rejecting unsafe values. */
  rawNumbers?: boolean;
}

export const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const NUMBER_RE = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
const ESCAPES: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

export function parseStrictJson(text: string, opts: StrictJsonOptions): unknown {
  let i = 0;
  const n = text.length;

  const fail = (msg: string, kind: JsonError["kind"] = "syntax"): never => {
    throw new JsonError(`${msg} at ${i}`, kind);
  };
  const ws = () => {
    for (;;) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else return;
    }
  };

  const hex4 = (): number => {
    const h = text.slice(i, i + 4);
    if (!/^[0-9A-Fa-f]{4}$/.test(h)) fail("bad \\u escape");
    i += 4;
    return parseInt(h, 16);
  };

  const str = (): string => {
    i++; // opening quote
    let out = "";
    let start = i;
    for (;;) {
      if (i >= n) fail("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(start, i);
        i++;
        return out;
      }
      if (c < 0x20) fail("control character in string");
      if (c === 0x5c) {
        out += text.slice(start, i);
        const e = text[i + 1];
        i += 2;
        if (e === "u") {
          const cu = hex4();
          if (cu >= 0xd800 && cu <= 0xdbff) {
            if (text[i] !== "\\" || text[i + 1] !== "u") fail("lone surrogate", "surrogate");
            i += 2;
            const lo = hex4();
            if (lo < 0xdc00 || lo > 0xdfff) fail("lone surrogate", "surrogate");
            out += String.fromCharCode(cu, lo);
          } else if (cu >= 0xdc00 && cu <= 0xdfff) {
            fail("lone surrogate", "surrogate");
          } else {
            out += String.fromCharCode(cu);
          }
        } else if (e !== undefined && Object.hasOwn(ESCAPES, e)) {
          out += ESCAPES[e];
        } else {
          fail("bad escape");
        }
        start = i;
        continue;
      }
      // Raw lone surrogates cannot come from strict UTF-8 decoding, but callers may pass
      // strings from elsewhere.
      if (c >= 0xd800 && c <= 0xdfff) {
        const next = text.charCodeAt(i + 1);
        if (c > 0xdbff || !(next >= 0xdc00 && next <= 0xdfff)) fail("lone surrogate", "surrogate");
        i += 2;
        continue;
      }
      i++;
    }
  };

  const num = (): number | RawNumber => {
    NUMBER_RE.lastIndex = i;
    const m = NUMBER_RE.exec(text);
    if (!m) return fail("bad number");
    i += m[0].length;
    const raw = m[0];
    if (opts.rawNumbers) return new RawNumber(raw);
    const v = Number(raw);
    if (!Number.isFinite(v)) fail("number out of range", "number");
    if (!/[.eE]/.test(raw) && !Number.isSafeInteger(v)) fail("integer exceeds 2^53", "number");
    return v;
  };

  const lit = (word: string, value: unknown): unknown => {
    if (text.startsWith(word, i)) {
      i += word.length;
      return value;
    }
    return fail("unexpected token");
  };

  const value = (depth: number): unknown => {
    ws();
    const c = text[i];
    if (c === "{" || c === "[") {
      if (depth >= opts.maxDepth) fail("nesting too deep", "depth");
      i++;
      ws();
      if (c === "[") {
        const arr: unknown[] = [];
        if (text[i] === "]") {
          i++;
          return arr;
        }
        for (;;) {
          arr.push(value(depth + 1));
          ws();
          if (text[i] === ",") {
            i++;
            continue;
          }
          if (text[i] === "]") {
            i++;
            return arr;
          }
          fail("expected , or ]");
        }
      }
      const obj: Record<string, unknown> = {};
      const seen = new Set<string>();
      if (text[i] === "}") {
        i++;
        return obj;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected key");
        const key = str();
        if (seen.has(key)) fail("duplicate key", "duplicate");
        if (opts.forbidKeys && FORBIDDEN_KEYS.has(key)) fail("forbidden key", "forbidden-key");
        seen.add(key);
        ws();
        if (text[i] !== ":") fail("expected :");
        i++;
        Object.defineProperty(obj, key, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return obj;
        }
        fail("expected , or }");
      }
    }
    if (c === '"') return str();
    if (c === "t") return lit("true", true);
    if (c === "f") return lit("false", false);
    if (c === "n") return lit("null", null);
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return num();
    return fail("unexpected token");
  };

  const out = value(0);
  ws();
  if (i !== n) fail("trailing data");
  return out;
}

/** JSON.stringify with RawNumber support (exact source text) and the same layout. */
export function stringifyWithRaw(value: unknown, indent = 1, level = 0): string {
  if (value instanceof RawNumber) return value.raw;
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  const pad = "\n" + " ".repeat(indent * (level + 1));
  const end = "\n" + " ".repeat(indent * level);
  if (Array.isArray(value)) {
    if (!value.length) return "[]";
    return `[${value.map((v) => pad + stringifyWithRaw(v, indent, level + 1)).join(",")}${end}]`;
  }
  const keys = Object.keys(value);
  if (!keys.length) return "{}";
  const obj = value as Record<string, unknown>;
  return `{${keys.map((k) => `${pad}${JSON.stringify(k)}: ${stringifyWithRaw(obj[k], indent, level + 1)}`).join(",")}${end}}`;
}
