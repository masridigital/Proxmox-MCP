// Per-user daily cap. The Rate Limiting binding handles the per-minute limit, but it counts
// per Cloudflare location and only supports 10 s / 60 s windows, so a day-long cap needs a
// strongly consistent counter: one small Durable Object per user (named by sha256 of the
// email, so the email is not the object name). It stores one record {day, count}.

import type { Env } from "./config";
import { sha256Hex } from "./util";

interface StorageLike {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
}
interface StateLike {
  storage: StorageLike;
  blockConcurrencyWhile<T>(fn: () => Promise<T>): Promise<T>;
}

export class DailyQuota {
  constructor(private state: StateLike) {}

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const limit = Number(url.searchParams.get("limit"));
    if (request.method !== "POST" || url.pathname !== "/hit" || !Number.isInteger(limit) || limit < 1) {
      return new Response(null, { status: 400 });
    }
    const day = new Date().toISOString().slice(0, 10);
    const allowed = await this.state.blockConcurrencyWhile(async () => {
      const cur = (await this.state.storage.get<{ day: string; count: number }>("q")) ?? { day, count: 0 };
      const count = cur.day === day ? cur.count : 0;
      if (count >= limit) return false;
      await this.state.storage.put("q", { day, count: count + 1 });
      return true;
    });
    return Response.json({ allowed });
  }
}

/** true when the call may proceed. Fails closed if the counter cannot be reached. */
export async function takeDaily(env: Env, user: string, limit: number): Promise<boolean> {
  try {
    const stub = env.DAILY_QUOTA.get(env.DAILY_QUOTA.idFromName(await sha256Hex(`quota:${user}`)));
    const res = await stub.fetch(`https://daily-quota/hit?limit=${limit}`, { method: "POST" });
    if (!res.ok) return false;
    const body = (await res.json()) as { allowed?: unknown };
    return body.allowed === true;
  } catch {
    return false;
  }
}

export async function takeMinute(env: Env, user: string): Promise<boolean> {
  try {
    const { success } = await env.RATE_LIMITER.limit({ key: await sha256Hex(`rate:${user}`) });
    return success === true;
  } catch {
    return false;
  }
}
