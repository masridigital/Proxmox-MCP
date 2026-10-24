import { describe, expect, it } from "vitest";
import { AuditChain, verifyChain } from "../src/audit";
import { memoryState } from "./helpers";

function setup() {
  const state = memoryState();
  const objects = new Map<string, string>();
  const bucket = {
    async put(key: string, value: string) {
      if (objects.has(key)) throw new Error("overwrite refused");
      objects.set(key, value);
      return {};
    },
  };
  const chain = new AuditChain(state as never, { AUDIT_BUCKET: bucket });
  const append = (rec: Record<string, unknown>) =>
    chain.fetch(new Request("https://audit-chain/append", { method: "POST", body: JSON.stringify(rec) }));
  return { state, objects, chain, append };
}

describe("AuditChain Durable Object", () => {
  it("hash-chains records and ships them to R2 on the alarm", async () => {
    const { state, objects, chain, append } = setup();
    for (let i = 0; i < 5; i++) expect((await append({ ts: "2026-10-24T01:02:03.000Z", event: "request", user: "a@x.com", i })).status).toBe(204);
    expect(await state.storage.getAlarm()).not.toBeNull();
    await chain.alarm();
    expect(objects.size).toBe(1);
    const [key, body] = [...objects.entries()][0]!;
    expect(key).toBe("worker-audit/2026/10/24/000000000001-000000000005.jsonl");
    const lines = body.trim().split("\n");
    expect(lines).toHaveLength(5);
    expect(await verifyChain(lines)).toBe(0);
    expect((await state.storage.list({ prefix: "p:" })).size).toBe(0);

    // The chain continues across batches.
    await append({ event: "request", i: 6 });
    await chain.alarm();
    const second = [...objects.values()][1]!.trim().split("\n");
    expect(await verifyChain([...lines, ...second])).toBe(0);
  });

  it("detects tampering, deletion and reordering", async () => {
    const { objects, chain, append } = setup();
    for (let i = 0; i < 4; i++) await append({ event: "request", i });
    await chain.alarm();
    const lines = [...objects.values()][0]!.trim().split("\n");
    const tampered = [...lines];
    tampered[1] = tampered[1]!.replace('"i":1', '"i":9');
    expect(await verifyChain(tampered)).toBeGreaterThan(0);
    expect(await verifyChain([lines[0]!, lines[2]!, lines[3]!])).toBeGreaterThan(0);
    expect(await verifyChain([lines[1]!, lines[0]!, lines[2]!, lines[3]!])).toBeGreaterThan(0);
  });

  it("flushes more than 128 lines (Durable Object delete limit) in one batch", async () => {
    const { state, objects, chain, append } = setup();
    const del = state.storage.delete.bind(state.storage);
    state.storage.delete = async (keys: string[]) => {
      if (keys.length > 128) throw new Error("too many keys");
      return del(keys);
    };
    for (let i = 0; i < 300; i++) await append({ event: "request", i });
    await chain.alarm();
    expect(objects.size).toBe(1);
    expect((await state.storage.list({ prefix: "p:" })).size).toBe(0);
  });

  it("rejects non-object and oversize records", async () => {
    const { append, chain } = setup();
    expect((await chain.fetch(new Request("https://audit-chain/append", { method: "POST", body: "[1]" }))).status).toBe(400);
    expect((await append({ big: "x".repeat(9000) })).status).toBe(400);
    expect((await chain.fetch(new Request("https://audit-chain/other", { method: "POST", body: "{}" }))).status).toBe(404);
  });
});
