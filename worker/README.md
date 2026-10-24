# proxmox-mcp Worker

Cloudflare Worker that is the **inbound MCP gateway** (MCP-STD-01 `:8090` role) for the
Proxmox MCP broker. Claude reaches it through the Cloudflare MCP Server Portal and an Access
self-hosted application; the Worker re-checks identity, speaks MCP, applies the STD-02
three-tool routing, rate limits, filters output and audits. It holds **no Proxmox credential**:
execution happens on the on-prem broker (`/v1/catalog`, `/v1/execute`), which re-checks policy
and is the final authority.

```
Claude -> MCP Server Portal -> Access app (Managed OAuth, Entra, named users)
       -> Worker POST /mcp  (this project)
       -> Workers VPC Service binding (or Access service token) -> cloudflared -> broker 127.0.0.1
```

## Request pipeline (fail closed at every step)

| # | Check | Failure |
|---|---|---|
| 1 | Path is `/mcp` | 404 |
| 2 | Configuration complete and well formed (`src/config.ts`): every var validated, `<placeholders>` and malformed optional lists refused, signing key must import as Ed25519 PKCS8 | 503 |
| 3 | `Host` equals `WORKER_HOSTNAME` (DNS-rebinding defence) | 421 |
| 4 | `Origin` absent or in `ALLOWED_ORIGINS` (empty by default) | 403 |
| 5 | Method is POST (GET/DELETE -> 405, no SSE) | 405 |
| 6 | `Cf-Access-Jwt-Assertion`: RS256 only, team JWKS (10 min cache, one in-flight fetch per isolate, refresh on unknown kid at most every 30 s, 5 s back-off after a failed fetch; only `e=AQAB`, >= 2048-bit, unique kids), no `jku`/`jwk`/`x5u`/`x5c`/`crit`, `typ` absent or `JWT`, `iss` exact, `aud` includes `CF_ACCESS_AUD`, `exp`/`nbf`/`iat` with 60 s leeway, `sub` + `email` required, `type` absent or `app`, service tokens (`common_name`) refused. Email must be printable ASCII **before** lowercasing (U+212A KELVIN SIGN folds to `k`) and match the broker's `sub` pattern | 401 + `WWW-Authenticate`, 403, 503 if JWKS unreachable |
| 7 | `Cf-Access-Authenticated-User-Email` (if present) equals JWT email; optional `ALLOWED_EMAILS` / `ALLOWED_EMAIL_DOMAINS` | 403 |
| 8 | Per-user 60/min (Rate Limiting binding) | 429 / -32000 |
| 9 | `Content-Type: application/json` (only parameter allowed: `charset=utf-8`), body <= 256 KB (Content-Length and actual bytes), strict UTF-8, strict RFC 8259 JSON (`src/json-strict.ts`): no BOM, no duplicate keys, depth <= 32, no lone surrogate escapes, no number that changes value (non-finite, integers beyond 2^53) | 415 / 413 / -32700 |
| 9a | No `__proto__` / `constructor` / `prototype` key anywhere in the message | -32600 |
| 10 | JSON-RPC: one object, `jsonrpc:"2.0"`, no batches, no responses, id string/integer | -32600 |
| 11 | Protocol version and headers (below) | -32020 / -32022 |
| 12 | Method allowlist: `initialize`, `ping` (legacy), `tools/list`, `tools/call`, `server/discover`, `notifications/initialized`, `notifications/cancelled` | -32601 |
| 13 | `tools/call` only for the three meta-tools; per-user daily cap (2000, Durable Object) | -32602 / 429 |
| 14 | Catalog from broker per user (60 s cache); unknown/hidden tools are never forwarded | isError `Unknown tool: X` |
| 15 | Broker result: 2 MiB cap, strict JSON, redirects refused, 25 s timeout; PHI + secret redaction (superset of `proxmox_mcp/phi.py` + `output.py`); untrusted-data label with a per-response nonce | isError with a short generic message |
| 16 | One audit line per request (no argument values; unknown RPC methods logged as `other`; argument keys that are not identifiers or look like PHI logged as `[key]`) | - |

## MCP protocol support

Stateless JSON responses only (no sessions, no SSE). Dual-era per MCP 2026-07-28
"Versioning: Backward Compatibility":

* **Legacy** `2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`: `initialize` negotiates
  (an unknown requested version gets `2025-11-25`); `MCP-Protocol-Version` header optional
  (absent = `2025-03-26`), otherwise must be a legacy version. Unknown methods answer HTTP 200
  with -32601, because a 404 tells 2025-era clients their session expired.
* **Modern** `2026-07-28`: no handshake. `params._meta["io.modelcontextprotocol/protocolVersion"]`
  must equal `MCP-Protocol-Version`, `Mcp-Method` must equal the method and `Mcp-Name` the
  tool name (Base64 sentinel decoded), else 400 / -32020. Unsupported version -> 400 / -32022
  with `{supported, requested}`. Results carry `resultType: "complete"` and `serverInfo` in
  `_meta`; `tools/list` and `server/discover` carry `ttlMs` + `cacheScope`.

## Tools (MCP-STD-02)

| Tool | Annotations | Behaviour |
|---|---|---|
| `list_tools` | read-only, idempotent | No terms: category summary (deliberate deviation from STD-02 "full catalog": ~450 tools). Terms: literal case-insensitive substring on name OR description, terms OR-ed. `content[0]` is always a JSON array of `{name, description}`; over 50 hits it holds the first 50 and `content[1]` says how many matched |
| `describe_tool_input` | read-only, idempotent | `<input_schema tool="...">` blocks (schema JSON with `<`/`>` \u-escaped so it cannot forge a delimiter); hidden and nonexistent tools both answer `Unknown tool: X` |
| `execute_tool` | destructive, open world | `POST /v1/execute {tool, arguments}` -> `{ok, text}`; `ok:false` -> isError. The broker router's `Unknown tool: X` / `Invalid input for tool X: ...` are passed through as plain STD-02 texts (redacted, one line, <= 500 chars); every other result is labelled untrusted data |

The catalog is `GET /v1/catalog` -> `{mode, version, tools:[{name, description, inputSchema, tier}]}`,
already filtered by the broker for the caller's enrollment mode.

## Output filter

`src/output.ts` runs on every broker result even though the broker already filtered it:

1. The broker's own envelope (`output.py` label + `<untrusted-data source="proxmox-api">`) is
   unwrapped once, so the model sees one label, not two.
2. If the body is JSON it is parsed strictly with numbers kept as source text (64-bit
   integers survive), secret-looking keys (`output.py` `SECRET_KEY_RE`, `keyboard`/`keymap`
   exempt) lose their whole value, every string goes through text redaction, and the JSON is
   re-serialised with `<`, `>`, `&` and bracket look-alikes (fullwidth, angle quotes, CJK
   brackets, ...) `\u`-escaped. Otherwise the text is redacted and those characters become
   `&lt;` / `&gt;`.
3. Text redaction = secrets (PEM incl. unterminated, `PVEAPIToken=`, `PVEAuthCookie=`, PVE
   tickets, `Authorization: Bearer|Basic`, `key: value` pairs with a secret key name) then
   PHI as `[REDACTED <type>]`: every `phi.py` rule (labelled/dashed SSN, MBI, MRN, DOB in all
   its date forms, brand+length+Luhn cards) plus broader Worker rules (space-separated SSN,
   case-insensitive MBI, issuer-prefixed cards). Emails/phones with `PHI_CONTACT=1`.
4. More than 2 MiB after filtering -> `result exceeds 2097152 bytes; narrow the query`
   (refused, not truncated: a cut JSON document misleads).
5. The label's delimiters are `<untrusted-data-<32 hex nonce>>`, fresh per response, so data
   cannot guess the closing tag; no `<` or `>` remains inside anyway.

CPU: a 1.7 MB result takes about 0.4 s to filter in Node 22; deploy on the Workers Standard
usage model (30 s CPU), not a 10 ms plan.

## Identity assertion to the broker (`X-MCP-Identity`)

Compact JWS, header `{"alg":"EdDSA","typ":"JWT","kid":IDENTITY_KEY_ID}`, Ed25519 via WebCrypto
(`{name:"Ed25519"}`), claims `iss=proxmox-mcp-worker`, `aud=proxmox-broker`, `sub` (lowercase
email), `iat`, `exp=iat+60`, `jti` (UUID), `ray` (Cf-Ray), `req` (sha256 hex of the exact body
bytes; empty body for GET), `method`, `path` (no query). `test/fixtures/assertion-vector.json`
is a **test-only** key pair and JWS that the Python broker tests verify; the Worker test
re-signs it byte for byte (Ed25519 is deterministic). Regenerate with `npm run gen-vector`.

Create the real key pair offline (never in chat or CI):

```sh
openssl genpkey -algorithm ed25519 -out identity.key          # PKCS8 PEM
openssl pkey -in identity.key -pubout -out identity.pub       # SPKI PEM, goes to the broker
npx wrangler secret put IDENTITY_SIGNING_KEY < identity.key
shred -u identity.key
```

## Configuration

`wrangler.jsonc` is a **template**; deploy tooling fills the placeholders.

| Name | Kind | Purpose |
|---|---|---|
| `CF_ACCESS_TEAM_DOMAIN` | var | `https://<team>.cloudflareaccess.com` (issuer + JWKS) |
| `CF_ACCESS_AUD` | var | AUD tag(s) of the Worker's Access app (comma list) |
| `WORKER_HOSTNAME` | var | Custom domain; `Host` must equal it |
| `BROKER_MODE` | var | `vpc` (preferred) or `access` |
| `BROKER_URL` | var | vpc: `http://broker.internal`; access: `https://<broker-hostname>` |
| `IDENTITY_KEY_ID` | var | `kid` of the identity key |
| `ALLOWED_EMAILS`, `ALLOWED_EMAIL_DOMAINS` | var | Optional second gate (Access policy is primary, broker enrollment is final) |
| `ALLOWED_ORIGINS` | var | Empty: any `Origin` header is refused (the portal is server to server) |
| `RATE_PER_DAY` | var | Daily `tools/call` cap per user (default 2000) |
| `PHI_CONTACT` | var | `1`: also redact emails and phone numbers (match the broker's `MCP_PHI_CONTACT`) |
| `IDENTITY_SIGNING_KEY` | secret | Ed25519 private key, PKCS8 PEM |
| `BROKER_ACCESS_CLIENT_ID` / `_SECRET` | secret | access mode only: service token for the broker's Access app |
| `BROKER` | `vpc_services` | Workers VPC Service binding (vpc mode) |
| `RATE_LIMITER` | `ratelimits` | 60 / 60 s; the limit is set in `wrangler.jsonc`, not a var |
| `DAILY_QUOTA` | Durable Object | `DailyQuota`, one per user (named by sha256 of the email) |
| `AUDIT_CHAIN` + `AUDIT_BUCKET` | Durable Object + R2 | Optional hash-chained audit batches to R2 (bucket lock outside code) |

`workers_dev` and `preview_urls` are off so no hostname bypasses Access. `observability` is on
with `head_sampling_rate: 1` so every request reaches Workers Logs / Logpush.

## Audit

Every request logs one JSON line: `ts, v, event (request|denied|config_error), user, ray, rpc,
tool, target, arg_keys, args_sha256, catalog_version, broker_status, broker_jti, deny, status,
is_error, bytes, ms`. Never argument values, results, tokens or PHI. `broker_jti` + `ray`
correlate with the broker's audit line. With `AUDIT_CHAIN` bound, each line is also appended
to a single-writer hash chain (`seq`, `ph` = sha256 of the previous stored line) and shipped every
5 minutes (or every 500 lines) to R2 as `worker-audit/YYYY/MM/DD/<first>-<last>.jsonl` (the date is
the first record's `ts`, so a retry targets the same object name). A batch is pinned in DO storage
until it is confirmed stored; a failed write logs `audit_flush_error`, keeps the lines and re-arms
the alarm in 60 s; if the write was refused because the object already exists (bucket lock after a
crash between write and delete), a `head()` with the same size counts as stored. Deletes are chunked
to the DO limit of 128 keys. `verifyChain()` in `src/audit.ts` checks a sequence.

## Dependencies

Runtime: **none**. The Worker uses Web APIs only (WebCrypto, fetch, streams), no
`nodejs_compat`. MCP is five JSON-RPC methods over stateless HTTP, so a hand-written handler
(`src/protocol.ts`, `src/index.ts`) replaces `@modelcontextprotocol/sdk` 1.32.2, which pulls in
17 runtime packages (express, hono, ajv, zod, jose, cors, ...), targets Node servers for its
HTTP transports and, as of that release, does not implement the 2026-07-28 revision. Dev only,
exact pins with `package-lock.json`:

| Package | Why |
|---|---|
| `typescript` 6.0.3 | typecheck (`tsc --noEmit`) |
| `@cloudflare/workers-types` 5.20261008.1 | Workers type definitions |
| `vitest` 5.0.3 | tests in plain Node 22 (WebCrypto RSA + Ed25519, fetch, streams) |
| `wrangler` 4.149.0 | config validation / dry-run bundle and deploy |

`overrides.undici = 7.30.1` patches a high-severity advisory in wrangler's local-dev
dependency chain (miniflare). npm 10.9 (bundled with Node 22) crashes resolving vitest 5's
peer set on `npm install`; the lockfile was produced with npm 11 and `npm ci` works with npm 10.
The repository root `.gitignore` ignores `package-lock.json`; `worker/.gitignore` re-includes it
so the pinned tree is committed (CC8.1).

## Commands

```sh
npm ci --ignore-scripts
npm run typecheck
npm test
npm audit --omit=dev
npm run check-config      # wrangler deploy --dry-run
```
