# Architecture: Proxmox MCP behind Cloudflare (V2)

This document describes the data path, the trust boundaries and the controls. It maps each
control to MCP-STD-01 (Secure Remote MCP Gateway) and MCP-STD-02 (Dynamic Tool Routing).
It also lists the open gaps of the KSM MCP precedent and how this build closes them.

All names in this document are placeholders. Real values live only in the deployment state
on the admin workstation and on the broker.

## 1. Components

| Component | Runs where | Role | Code / config |
|---|---|---|---|
| Claude (claude.ai, Desktop, Code) | Anthropic | MCP client | n/a |
| MCP server portal | Cloudflare Zero Trust | Lists the server for users, Access policy at the portal | `deploy/cloudflare/provision.sh` (portal step) |
| Access app on `<worker-hostname>` | Cloudflare Access | Managed OAuth (DCR), named users, Entra login required | `provision.sh` (access step) |
| Worker `proxmox-mcp` | Cloudflare Workers | Inbound gateway: MCP protocol, JWT re-check, routing, tool filter, rate limit, labels, audit | `worker/` |
| R2 bucket `<audit-bucket>` | Cloudflare R2 | Worker audit batches, bucket lock 2190 days | `provision.sh` (r2 step) |
| Workers VPC Service (beta) | Cloudflare | Private route Worker to broker tunnel, no public hostname | `provision.sh` (broker step, vpc mode) |
| Fallback: Access app on `<broker-hostname>` | Cloudflare Access | Service token only (`non_identity`) | `provision.sh` (broker step, access mode) |
| Tunnel `proxmox-mcp-broker` | Cloudflare + broker | Remote-managed, outbound only, catch-all 404 | `provision.sh` (tunnel step) |
| `cloudflared-proxmox-mcp` service | Windows broker | Tunnel connector, virtual account, token from file | `deploy/windows/Install-Cloudflared.ps1` |
| `ProxmoxMCPBroker` service | Windows broker | Outbound gateway: assertion check, policy re-check, tool execution, outbound allowlist, per-user token, TLS pin, audit | `proxmox_mcp/`, `deploy/windows/Install-ProxmoxMcpBroker.ps1` |
| Audit shipping task | Windows broker | Ships audit bytes every 5 min to Azure Blob (WORM) | `deploy/windows/Send-AuditLog.ps1` |
| Proxmox VE | LAN | API on 8006, per-user privilege-separated tokens, pool-scoped ACLs | `deploy/proxmox/setup-proxmox-access.sh` |

## 2. Data path

```
 Claude (Anthropic)                                   [Boundary A: internet]
   | HTTPS, OAuth bearer from Access Managed OAuth
   v
 Cloudflare edge: MCP server portal -> Access app <worker-hostname>
   | Access checks: OAuth token (10 min), session (8 h), policy: named email AND login method Entra
   | Adds Cf-Access-Jwt-Assertion (RS256, aud = Worker app AUD)
   v
 Worker "proxmox-mcp"                                  [Boundary B: Cloudflare account]
   | re-validates the Access JWT (JWKS, iss, aud, exp)  -> user email
   | JSON-RPC allowlist, no batch, 256 KB cap, rate limit 60/min + 2000/day per user
   | list_tools / describe_tool_input / execute_tool over the broker catalog (filtered per user)
   | signs X-MCP-Identity (Ed25519, 60 s, jti, body hash, method + path)
   v
 [vpc]    VPC Service binding BROKER -> tunnel -> 127.0.0.1:8765        (no public hostname)
 [access] https://<broker-hostname> + CF-Access-Client-Id/Secret
          -> Access app (service token only) -> tunnel (access.required, broker AUD) -> 127.0.0.1:8765
   v
 cloudflared-proxmox-mcp (Windows service, NT SERVICE\cloudflared-proxmox-mcp)
   | outbound only: TCP/UDP 7844, TCP 443
   v                                                   [Boundary C: broker host]
 ProxmoxMCPBroker on 127.0.0.1:8765 (NT SERVICE\ProxmoxMCPBroker)
   | access mode: verifies the service-token JWT (aud = broker app AUD, common_name = Worker client id)
   | verifies X-MCP-Identity: EdDSA with the Worker public key, iss, aud, exp <= 60 s, jti replay cache,
   |   body hash, method + path. Host header must be MCP_ALLOWED_HOSTS (broker.internal in vpc mode).
   | enrollment.json: email -> mode (ro | operator | rw) -> Proxmox user + token credential
   | tool tier vs mode (final decision), outbound method + path allowlist, path segment checks
   | output: PHI redaction, secret redaction, 2 MB cap, untrusted-data label
   | audit: hash-chained JSONL, Cf-Ray and jti for correlation
   v                                                   [Boundary D: LAN]
 Proxmox VE API https://<proxmox-host>:8006
   | TLS pinned (SHA-256 fingerprint) or CA bundle; per-user token mcp-<short>@pve!mcp (privsep=1)
   | ACL: role ProxmoxMCP-Read | -Operate | -Admin on /pool/<pool> only
```

GET `/healthz` on the broker answers 200 `ok` to local callers only. `/v1/catalog` and
`/v1/execute` need both checks above.

## 3. Trust boundaries

| Boundary | What crosses it | What protects it |
|---|---|---|
| A. Internet to Cloudflare | User OAuth tokens, MCP JSON-RPC | Access Managed OAuth (PKCE, DCR limited to Claude callbacks and loopback), Entra login with Conditional Access MFA, named-user policy, 10 min access token, 8 h session |
| B. Cloudflare account | Worker code, Worker secrets, Access config, tunnel config | Account roles and MFA for Cloudflare admins, audit logs, provisioning by script with a scoped API token. The Worker holds NO Proxmox credential. |
| C. Cloudflare to broker host | Signed identity assertions and tool calls | Tunnel (outbound only, no inbound port), loopback bind, identity assertion verified with a public key, optional Access service-token JWT, replay cache, body binding |
| D. Broker to Proxmox | API calls as the person | Per-user privilege-separated tokens (DPAPI at rest, never leave the broker), pool-scoped roles, TLS pin, Windows Firewall program rules |

The Worker and the broker split the two gateway listeners of MCP-STD-01. The Worker is the
inbound gateway (`:8090`). The broker is the outbound gateway (`:8091`). The broker repeats
every decision that grants access. A Worker defect can show a user a tool. It cannot make the
broker run it.

## 4. Control map

| # | Control | Where | MCP-STD-01 / 02 rule |
|---|---|---|---|
| 1 | Client never holds an application credential | Claude holds only Access OAuth tokens. Proxmox tokens stay in DPAPI on the broker. | STD-01 §1 rule 2 |
| 2 | One person, one key | `mcp-<short>@pve` with one privsep token per person; enrollment maps email to token credential | STD-01 §1 rule 3 |
| 3 | Fail closed | Missing enrollment, unknown user, bad assertion, missing credential: deny. Broker exits with code 2 on missing config. | STD-01 §1 rule 7 |
| 4 | Identity from the IdP | Access with Entra, `require login_method`, named users | STD-01 §3 option (b)/(c) |
| 5 | DCR limited to Claude callbacks | Access `oauth_configuration.dynamic_client_registration.allowed_uris` | STD-01 §4 |
| 6 | Unauthenticated `/mcp` gives 401 with `WWW-Authenticate` | Access Managed OAuth, checked by `provision.sh` verify | STD-01 §4, §9 |
| 7 | JSON-RPC allowlist, no batches, 256 KB | Worker (first), broker body cap (second) | STD-01 §5.3 |
| 8 | Inbound tool policy | Worker filters `list_tools`; broker `policy.check_tool` decides | STD-01 §5.5, STD-02 §5 |
| 9 | Outbound path and method policy | Broker `outbound.py` | STD-01 §5.5 |
| 10 | Human-only actions stay human-only | Forbidden tier in `policy.py`; Proxmox roles exclude console, guest agent, users, ACL, realm, Sys.Modify | STD-01 §1 rule 6 |
| 11 | Rate limits 60/min, 2000/day | Worker rate limit binding and DailyQuota Durable Object; broker limiter | STD-01 §5.5 |
| 12 | Untrusted-data label, size cap | Broker `output.py`, Worker second layer | STD-01 §5.5 |
| 13 | Hash-chained audit, shipped | Broker JSONL to Azure Blob WORM (5 min). Worker AuditChain to R2 with bucket lock. | STD-01 §5.9 |
| 14 | `list_tools` hides tools the caller cannot run | Catalog filtered per mode on the broker and in the Worker | STD-02 §6 (gap closed) |
| 15 | No secret on a command line or in chat | All secrets via stdin or hidden prompt; tunnel token by file; checked by `Test-ProxmoxMcpBroker.ps1` | STD-01 §5.8 |
| 16 | DRY_RUN / WhatIf before change | `provision.sh DRY_RUN=1`, every PowerShell script `-WhatIf` | STD-01 §7 |

## 5. KSM precedent: open gaps and how V2 closes them

| KSM gap | V2 control |
|---|---|
| No server-side tool filter (every tool visible and callable if the upstream allowed it) | Tool tiers on the broker (read, operate, admin, forbidden). Default read-only. Admin tier needs rw mode and `MCP_ALLOW_ADMIN_TOOLS=1`. `list_tools` hides denied tools. |
| No untrusted-data label (prompt injection through VM names, notes, descriptions) | Every text result starts with an untrusted-data label. Secrets and PHI patterns are redacted. Guest-content tools are forbidden. |
| No audit shipping or hash chain | Broker JSONL with `ph` hash chain, shipped every 5 min to Azure Blob with a locked 2190-day retention policy. Worker audit chain to R2 with bucket lock. `proxmox-mcp-audit-verify` and `Test-ShippedAudit.ps1` check both ends. |
| Origin trusted cloudflared to validate Access | The broker verifies its own inputs (signed identity assertion, and the service-token JWT in access mode). Loopback bind. |
| Shared cloudflared and LocalSystem services | Dedicated tunnel and service, virtual accounts, privileges reduced to `SeChangeNotifyPrivilege`. |
| 24 h OAuth grant | 8 h session and grant, 10 min access token. |

## 6. Deployment modes

| Mode | Broker reachability | Broker auth | Status |
|---|---|---|---|
| `vpc` (preferred) | Workers VPC Service to `127.0.0.1:8765` through the tunnel. No DNS record, no ingress hostname. | Identity assertion only (`BROKER_REQUIRE_ACCESS_JWT=0`), loopback bind, `MCP_ALLOWED_HOSTS=broker.internal` | Workers VPC is beta. Needs cloudflared 2025.7.0 or later and QUIC (UDP 7844). |
| `access` (fallback) | Public `<broker-hostname>` through the tunnel | Access app with one `non_identity` policy for the Worker service token; tunnel `access.required` with the broker AUD; broker checks the JWT and the assertion | Generally available features only |

Any account member with the Connectivity Directory Bind role can bind a Worker to the VPC
Service. The broker still refuses that Worker, because it cannot sign identity assertions.

## 7. Windows broker layout

| Path | Contents | ACL |
|---|---|---|
| `C:\Program Files\ProxmoxMCP\python` | Private Python (python.org installer, hash + signer checked; major.minor must equal the lock header) | Administrators, SYSTEM full; service read/execute |
| `C:\Program Files\ProxmoxMCP\venvs\<id>` | One venv per release (`<wheel sha>-<lock sha>-py<ver>`); the active and the previous one are kept for rollback | same |
| `C:\Program Files\ProxmoxMCP\installed.json` | Active and previous venv, wheel and lock hashes, Python version | Administrators, SYSTEM |
| `C:\Program Files\ProxmoxMCP\service` | WinSW v2.12.0 wrapper and XML | same as python |
| `C:\Program Files\ProxmoxMCP\scripts` | Copies of `deploy\windows` for the scheduled tasks | same |
| `C:\Program Files\ProxmoxMCP\staging` | Verified copies of artifacts during an install; deleted after | Administrators, SYSTEM only |
| `C:\ProgramData\ProxmoxMCP` | Parent, locked before any child is created | Administrators, SYSTEM full; service traverse |
| `...\credentials` | `enrollment.json` (plain), `*.dpapi` secrets, `worker-identity.pub`, `dpapi-entropy.bin` | Administrators, SYSTEM full; service read (per file: `audit-ship-sas` SYSTEM only, `pve-review-token` Administrators only); OWNER RIGHTS read; SACL on write, delete, ACL change and failed reads |
| `...\logs` | `audit.jsonl`, `audit-YYYYMM.jsonl`, `audit.jsonl.lock` | Service create/append (no delete, no ACL change: OWNER RIGHTS); SYSTEM full; Administrators read; SACL on delete and ACL change |
| `...\config` | `broker.env`, `ship.json`, `token-expiry.json` | Administrators, SYSTEM full; service read |
| `...\evidence` | Selfcheck reports, access reviews, key escrow records (uploaded once to WORM) | Administrators, SYSTEM |
| `...\ship` | Shipping state, immutability test results | Administrators, SYSTEM |
| `...\cloudflared` | `tunnel-token`, logs | Administrators, SYSTEM full; cloudflared service read (logs: modify) |

Service wrapper decision: WinSW v2.12.0 (`WinSW.NET461.exe`) pinned by SHA-256. Reasons:
Python cannot answer the Service Control Manager without pywin32, which the design excludes.
`sc.exe` around `python.exe` fails, because the SCM stops a process that does not report
`SERVICE_RUNNING`. NSSM has had no release since 2017. WinSW runs on the in-box .NET Framework
4.8.1, which Windows Update patches. WinSW is not Authenticode signed, so the hash pin and a
WDAC or AppLocker hash rule are the integrity controls.

Firewall program path: the venv `Scripts\python.exe` and the console-script `.exe` launchers
start the base interpreter `C:\Program Files\ProxmoxMCP\python\python.exe`, which opens the
sockets. The rules target that file, so they do not change when a new venv is installed.

Python version: the hashed lock names its CPython version in its header; the installer enforces
it. See docs/SECURITY.md T23 for the decision on the target line.

## 8. Configuration reference (broker.env)

`proxmox_mcp/config.py` loads this file's variables at start (role `broker`). It refuses an
unknown or malformed `PROXMOX_*`, `MCP_*`, `BROKER_*` or `CF_ACCESS_*` variable; booleans are
exactly `0` or `1`. The installer writes the file and validates it with the same parser before
the service uses it. Do not edit it by hand.

| Variable | Value written | Notes |
|---|---|---|
| `PROXMOX_HOST`, `PROXMOX_PORT` | `<proxmox-host>`, 8006 | |
| `PROXMOX_TLS_FINGERPRINT` or `PROXMOX_CA_BUNDLE` | SHA-256 of the PVE certificate, or an absolute CA file path | Mandatory. `PROXMOX_INSECURE_TLS` is never written. |
| `PROXMOX_TIMEOUT` | 30 | seconds per Proxmox request |
| `PROXMOX_TOTAL_TIMEOUT` | 120 | whole-request deadline, 1 to 3600 s |
| `MCP_BIND`, `MCP_PORT` | 127.0.0.1, 8765 | Non-loopback refused unless `MCP_ALLOW_NON_LOOPBACK=1`. Never set it. |
| `MCP_ALLOWED_HOSTS` | `broker.internal` (vpc) or `<broker-hostname>` (access) | Host header allowlist (`/healthz` is exempt) |
| `MCP_REQUEST_TIMEOUT` | 120 | seconds per request |
| `MCP_BODY_TIMEOUT` | 15 | seconds for the request body to arrive (slow-body defence) |
| `MCP_HEADER_TIMEOUT` | 10 | seconds for the request head to arrive (slow-header defence) |
| `MCP_MAX_CONCURRENCY` | 64 | |
| `MCP_MAX_REQUEST_BYTES`, `MCP_MAX_RESULT_BYTES` | 262144, 2097152 | |
| `MCP_RATE_PER_MIN`, `MCP_RATE_PER_DAY` | 60, 2000 | |
| `MCP_TOOL_MODE` | dynamic | |
| `MCP_ALLOW_ADMIN_TOOLS` | 0 | 1 (with `-AllowAdminTools`) enables the admin tier for rw users |
| `BROKER_REQUIRE_ACCESS_JWT` | 0 (vpc) or 1 (access) | 0 is reported as a dangerous flag in the start event, by design in vpc mode |
| `CF_ACCESS_TEAM_DOMAIN`, `CF_ACCESS_AUD` | team URL, broker app AUD | access mode only |
| `BROKER_ALLOWED_SERVICE_CLIENT_IDS` | Worker service token client id | access mode only |
| `MCP_ALLOW_SERVICE_TOKENS` | never written | |

Fixed by the installer (service XML, not broker.env):

| Variable | Value |
|---|---|
| `BROKER_CREDENTIALS_DIR` | `C:\ProgramData\ProxmoxMCP\credentials` |
| `BROKER_DPAPI_ENTROPY_FILE` | `...\credentials\dpapi-entropy.bin` |
| `MCP_ENROLLMENT_FILE` | `...\credentials\enrollment.json` |
| `MCP_AUDIT_LOG` | `C:\ProgramData\ProxmoxMCP\logs\audit.jsonl` |
| `MCP_AUDIT_HMAC` | `required` (no key, no audit, no service) |
| `PYTHONDONTWRITEBYTECODE`, `PYTHONNOUSERSITE`, `PYTHONUTF8` | 1 |

Operator tools that read the same configuration (run through `Invoke-PmcBrokerTool`, which
sets exactly the service environment): `proxmox-mcp-selfcheck [--live]` (exit 0 pass, 1 warn,
2 fail, 3 crash), `proxmox-mcp-audit-verify` (0 intact, 1 integrity failure, 2 usage or I/O),
`proxmox-mcp-protect-credential`.
