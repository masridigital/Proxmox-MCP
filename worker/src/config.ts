// Environment contract and fail-closed validation. Every value is checked on each request
// (cheap) so a bad deploy answers 503 instead of running half-configured.

import { csv } from "./util";

/** Minimal binding shapes (declared here so the code does not depend on runtime-only types). */
export interface FetcherLike {
  fetch(input: string | Request, init?: RequestInit): Promise<Response>;
}
export interface RateLimiterLike {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}
export interface DurableObjectStubLike {
  fetch(input: string | Request, init?: RequestInit): Promise<Response>;
}
export interface DurableObjectNamespaceLike {
  idFromName(name: string): unknown;
  get(id: unknown): DurableObjectStubLike;
}

export interface Env {
  // vars
  CF_ACCESS_TEAM_DOMAIN: string; // https://<team>.cloudflareaccess.com
  CF_ACCESS_AUD: string; // Worker Access app AUD tag(s), comma list
  WORKER_HOSTNAME: string; // <worker-hostname>, Host header must equal it
  BROKER_MODE: string; // "vpc" | "access"
  BROKER_URL: string; // vpc: http://broker.internal ; access: https://<broker-hostname>
  IDENTITY_KEY_ID: string; // kid of the Ed25519 identity key
  ALLOWED_EMAILS?: string; // optional second gate (comma list)
  ALLOWED_EMAIL_DOMAINS?: string; // optional second gate (comma list)
  ALLOWED_ORIGINS?: string; // browsers are not expected; empty = any Origin is refused
  RATE_PER_DAY?: string; // default 2000 tools/call per user per UTC day
  PHI_CONTACT?: string; // "1" also redacts emails and phone numbers (broker MCP_PHI_CONTACT)
  // secrets
  IDENTITY_SIGNING_KEY: string; // Ed25519 PKCS8 PEM
  BROKER_ACCESS_CLIENT_ID?: string; // access mode only
  BROKER_ACCESS_CLIENT_SECRET?: string; // access mode only
  // bindings
  BROKER?: FetcherLike; // vpc_services binding (vpc mode)
  RATE_LIMITER: RateLimiterLike; // ratelimits binding, 60/60 s per user
  DAILY_QUOTA: DurableObjectNamespaceLike; // DailyQuota Durable Object
  AUDIT_CHAIN?: DurableObjectNamespaceLike; // optional AuditChain Durable Object
}

export interface Config {
  teamDomain: string;
  audiences: string[];
  hostname: string;
  brokerMode: "vpc" | "access";
  brokerBase: string;
  keyId: string;
  allowedEmails: string[];
  allowedDomains: string[];
  allowedOrigins: string[];
  ratePerDay: number;
  phiContact: boolean;
}

const TEAM_RE = /^https:\/\/[a-z0-9-]{1,63}\.cloudflareaccess\.com$/;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const KID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const EMAIL_RE = /^[a-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/;
// Access service token: "<32 hex>.access" client id and a long opaque secret. Validated loosely
// (charset + length) so a format change does not break deploys, plus placeholder detection.
const CLIENT_ID_RE = /^[A-Za-z0-9._-]{16,128}$/;
const CLIENT_SECRET_RE = /^[A-Za-z0-9._~+/=-]{32,256}$/;
const PLACEHOLDER_RE = /[<>]|replace|change.?me|placeholder|example|xxxx|todo/i;
const PEM_RE = /^\s*-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\s]+-----END PRIVATE KEY-----\s*$/;

function origin(value: string): string {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    throw new ConfigError("ALLOWED_ORIGINS");
  }
  if (u.protocol !== "https:" || u.origin !== value || u.username || u.password) throw new ConfigError("ALLOWED_ORIGINS");
  return value;
}

export class ConfigError extends Error {}

export function loadConfig(env: Env): Config {
  const teamDomain = (env.CF_ACCESS_TEAM_DOMAIN ?? "").trim().replace(/\/+$/, "");
  if (!TEAM_RE.test(teamDomain)) throw new ConfigError("CF_ACCESS_TEAM_DOMAIN");
  const audiences = csv(env.CF_ACCESS_AUD);
  if (!audiences.length || audiences.some((a) => !/^[A-Za-z0-9]{16,128}$/.test(a))) throw new ConfigError("CF_ACCESS_AUD");
  const hostname = (env.WORKER_HOSTNAME ?? "").trim().toLowerCase();
  if (!HOST_RE.test(hostname)) throw new ConfigError("WORKER_HOSTNAME");

  const mode = env.BROKER_MODE;
  if (mode !== "vpc" && mode !== "access") throw new ConfigError("BROKER_MODE");
  let base: URL;
  try {
    base = new URL(env.BROKER_URL);
  } catch {
    throw new ConfigError("BROKER_URL");
  }
  const schemeOk = mode === "access" ? base.protocol === "https:" : base.protocol === "http:" || base.protocol === "https:";
  if (!schemeOk || base.username || base.password || base.search || base.hash || (base.pathname !== "/" && base.pathname !== "")) {
    throw new ConfigError("BROKER_URL");
  }
  if (mode === "vpc" && !env.BROKER) throw new ConfigError("BROKER binding");
  if (mode === "access") {
    const id = env.BROKER_ACCESS_CLIENT_ID ?? "";
    const secret = env.BROKER_ACCESS_CLIENT_SECRET ?? "";
    if (!CLIENT_ID_RE.test(id) || PLACEHOLDER_RE.test(id.replace(/\.access$/, ""))) throw new ConfigError("BROKER_ACCESS_CLIENT_ID");
    if (!CLIENT_SECRET_RE.test(secret) || PLACEHOLDER_RE.test(secret)) throw new ConfigError("BROKER_ACCESS_CLIENT_SECRET");
  }
  if (!KID_RE.test(env.IDENTITY_KEY_ID ?? "")) throw new ConfigError("IDENTITY_KEY_ID");
  if (!PEM_RE.test(env.IDENTITY_SIGNING_KEY ?? "")) throw new ConfigError("IDENTITY_SIGNING_KEY");
  if (!env.RATE_LIMITER || !env.DAILY_QUOTA) throw new ConfigError("rate limit bindings");

  const ratePerDay = env.RATE_PER_DAY ? Number(env.RATE_PER_DAY) : 2000;
  if (!/^\d{1,7}$/.test(env.RATE_PER_DAY ?? "2000") || !Number.isInteger(ratePerDay) || ratePerDay < 1 || ratePerDay > 1_000_000) {
    throw new ConfigError("RATE_PER_DAY");
  }
  const phi = (env.PHI_CONTACT ?? "").trim();
  if (!["", "0", "1"].includes(phi)) throw new ConfigError("PHI_CONTACT");

  // Optional gates: empty is allowed, but every entry that is present must be well formed,
  // so a "<placeholder>" or a typo fails closed (503) instead of silently matching nobody.
  const allowedEmails = csv(env.ALLOWED_EMAILS, true);
  if (allowedEmails.some((e) => !EMAIL_RE.test(e))) throw new ConfigError("ALLOWED_EMAILS");
  const allowedDomains = csv(env.ALLOWED_EMAIL_DOMAINS, true).map((d) => d.replace(/^@/, ""));
  if (allowedDomains.some((d) => !HOST_RE.test(d))) throw new ConfigError("ALLOWED_EMAIL_DOMAINS");
  const allowedOrigins = csv(env.ALLOWED_ORIGINS).map(origin);

  return {
    teamDomain,
    audiences,
    hostname,
    brokerMode: mode,
    brokerBase: base.origin,
    keyId: env.IDENTITY_KEY_ID,
    allowedEmails,
    allowedDomains,
    allowedOrigins,
    ratePerDay,
    phiContact: phi === "1",
  };
}
