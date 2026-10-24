// Audit events. One JSON line per event on console.log (Workers Logs / Logpush), and, when the
// AUDIT_CHAIN Durable Object is bound, the same record appended to a hash chain that is
// shipped in batches to an R2 bucket (bucket lock / retention is configured outside code).
// Records never contain argument values, results, tokens or PHI: argument keys and a sha256
// of the canonical arguments only.

import type { Env } from "./config";
import { sha256Hex } from "./util";

export interface AuditRecord {
  ts?: string;
  event: string; // request | denied | config_error
  user?: string;
  ray?: string;
  rpc?: string;
  tool?: string;
  target?: string;
  arg_keys?: string[];
  broker_status?: number;
  broker_jti?: string;
  catalog_version?: string;
  deny?: string;
  status?: number;
  is_error?: boolean;
  bytes?: number;
  ms?: number;
}

export const WORKER_VERSION = "0.1.0";

export function audit(env: Env, record: AuditRecord, waitUntil?: (p: Promise<unknown>) => void): void {
  const line = JSON.stringify({ ts: new Date().toISOString(), v: WORKER_VERSION, ...record });
  console.log(line);
  if (env.AUDIT_CHAIN && waitUntil) {
    const stub = env.AUDIT_CHAIN.get(env.AUDIT_CHAIN.idFromName("audit-v1"));
    waitUntil(
      stub
        .fetch("https://audit-chain/append", { method: "POST", body: line })
        .then((r) => {
          if (!r.ok) console.log(JSON.stringify({ event: "audit_chain_error", status: r.status }));
        })
        .catch(() => console.log(JSON.stringify({ event: "audit_chain_error" }))),
    );
  }
}

// ----------------------------------------------------------------------------- AuditChain DO

interface StorageLike {
  get<T>(key: string): Promise<T | undefined>;
  put(entries: Record<string, unknown>): Promise<void>;
  delete(keys: string[]): Promise<number>;
  list<T>(options: { prefix: string; limit?: number }): Promise<Map<string, T>>;
  getAlarm(): Promise<number | null>;
  setAlarm(time: number): Promise<void>;
}
interface StateLike {
  storage: StorageLike;
  blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T>;
}
interface R2Like {
  put(key: string, value: string, options?: { httpMetadata?: { contentType?: string } }): Promise<unknown>;
  head?(key: string): Promise<{ size: number } | null>;
}

export const FLUSH_INTERVAL_MS = 5 * 60_000;
const RETRY_MS = 60_000;
const FLUSH_BATCH = 1000;
const FLUSH_AT = 500; // pending lines that trigger an early flush
const MAX_LINE = 8192;
const GENESIS = "0".repeat(64);

/**
 * Single-instance hash chain. Each stored line is the original record plus
 * `seq` and `ph` (sha256 hex of the previous stored line). Pending lines are kept in
 * Durable Object storage until an alarm writes them to R2 as one JSONL object named by
 * its sequence range, then they are deleted. A failed R2 write keeps them for the next alarm.
 */
export class AuditChain {
  constructor(
    private state: StateLike,
    private env: { AUDIT_BUCKET?: R2Like },
  ) {}

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST" || new URL(request.url).pathname !== "/append") return new Response(null, { status: 404 });
    const text = await request.text();
    let record: Record<string, unknown>;
    try {
      record = JSON.parse(text) as Record<string, unknown>;
    } catch {
      return new Response(null, { status: 400 });
    }
    if (text.length > MAX_LINE || typeof record !== "object" || record === null || Array.isArray(record)) {
      return new Response(null, { status: 400 });
    }
    // Serialise appends so seq / ph never fork.
    await this.state.blockConcurrencyWhile(async () => {
      const s = this.state.storage;
      const head = (await s.get<{ seq: number; hash: string }>("head")) ?? { seq: 0, hash: GENESIS };
      const seq = head.seq + 1;
      const line = JSON.stringify({ ...record, seq, ph: head.hash });
      const hash = await sha256Hex(line);
      await s.put({ head: { seq, hash }, [`p:${String(seq).padStart(12, "0")}`]: line });
      const pending = (await s.get<number>("pending")) ?? 0;
      await s.put({ pending: pending + 1 });
      if (pending + 1 >= FLUSH_AT) await s.setAlarm(Date.now());
      else if ((await s.getAlarm()) === null) await s.setAlarm(Date.now() + FLUSH_INTERVAL_MS);
    });
    return new Response(null, { status: 204 });
  }

  async alarm(): Promise<void> {
    const s = this.state.storage;
    if (!this.env.AUDIT_BUCKET) {
      if ((await s.list<string>({ prefix: "p:", limit: 1 })).size) await s.setAlarm(Date.now() + FLUSH_INTERVAL_MS);
      return;
    }
    // A batch, once chosen, is pinned in storage until it is confirmed stored, so a retry
    // writes exactly the same object (same name, same bytes) even if new lines arrived.
    let batch = await s.get<{ first: string; last: string; count: number }>("batch");
    const lines = await s.list<string>({ prefix: "p:", limit: batch?.count ?? FLUSH_BATCH });
    if (!lines.size) {
      if (batch) await s.delete(["batch"]);
      return;
    }
    const keys = [...lines.keys()];
    if (!batch || keys[0] !== `p:${batch.first}` || keys[keys.length - 1] !== `p:${batch.last}`) {
      batch = { first: keys[0]!.slice(2), last: keys[keys.length - 1]!.slice(2), count: keys.length };
      await s.put({ batch });
    }
    const values = [...lines.values()];
    // The object name depends only on the batch (first record's day + sequence range), not
    // on the flush time. With bucket lock an overwrite is refused, so after "put succeeded,
    // delete failed" a head() that finds the object with the same size proves the batch is
    // stored and lets the chain move on instead of retrying forever.
    const name = `worker-audit/${batchDay(values[0]!)}/${batch.first}-${batch.last}.jsonl`;
    const body = `${values.join("\n")}\n`;
    try {
      await this.env.AUDIT_BUCKET.put(name, body, { httpMetadata: { contentType: "application/x-ndjson" } });
    } catch {
      let stored = false;
      try {
        const head = await this.env.AUDIT_BUCKET.head?.(name);
        stored = !!head && head.size === new TextEncoder().encode(body).byteLength;
      } catch {
        stored = false;
      }
      if (!stored) {
        // Keep the batch; the lines stay in DO storage until a write succeeds.
        console.log(JSON.stringify({ event: "audit_flush_error", first: batch.first, last: batch.last }));
        await s.setAlarm(Date.now() + RETRY_MS);
        return;
      }
    }
    // Durable Object storage deletes at most 128 keys per call.
    for (let i = 0; i < keys.length; i += 128) await s.delete(keys.slice(i, i + 128));
    await s.delete(["batch"]);
    const pending = (await s.get<number>("pending")) ?? 0;
    await s.put({ pending: Math.max(0, pending - keys.length) });
    const more = (await s.list<string>({ prefix: "p:", limit: 1 })).size > 0;
    await s.setAlarm(Date.now() + (more ? 1000 : FLUSH_INTERVAL_MS));
  }
}

/** UTC day of a stored line's `ts` as YYYY/MM/DD (deterministic per batch). */
function batchDay(line: string): string {
  try {
    const ts = (JSON.parse(line) as { ts?: unknown }).ts;
    if (typeof ts === "string" && /^\d{4}-\d{2}-\d{2}T/.test(ts)) return ts.slice(0, 10).replace(/-/g, "/");
  } catch {
    // fall through
  }
  return "undated";
}

/** Verify a chain of stored lines (as written to R2). Returns the number of breaks. */
export async function verifyChain(lines: string[], previousHash = GENESIS): Promise<number> {
  let breaks = 0;
  let prev = previousHash;
  let prevSeq: number | null = null;
  for (const line of lines) {
    let rec: { seq?: unknown; ph?: unknown };
    try {
      rec = JSON.parse(line) as { seq?: unknown; ph?: unknown };
    } catch {
      breaks++;
      continue;
    }
    if (rec.ph !== prev || (prevSeq !== null && rec.seq !== prevSeq + 1)) breaks++;
    prev = await sha256Hex(line);
    prevSeq = typeof rec.seq === "number" ? rec.seq : null;
  }
  return breaks;
}
