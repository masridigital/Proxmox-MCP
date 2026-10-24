# Proxmox MCP broker

This repository lets Claude operate a Proxmox VE cluster through the Model Context
Protocol (MCP), behind Cloudflare Access, with per-person accountability.

It is a fork of [ry-ops/proxmox-mcp-server](https://github.com/ry-ops/proxmox-mcp-server)
by ry-ops (MIT license), imported at upstream commit `7276144`. The 340 Proxmox tools
and their handlers are the upstream code. This fork adds the security layers around
them: identity, policy, per-user API tokens, verified TLS, output filters and a
hash-chained audit log.

## Contents

- [Setup](#setup)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Modes and tool tiers](#modes-and-tool-tiers)
- [Compliance gate](#compliance-gate)
- [Configuration](#configuration)
- [Local development](#local-development)
- [Tests](#tests)
- [Documents](#documents)
- [Changes from upstream](#changes-from-upstream)
- [Credits and license](#credits-and-license)

## Setup

The deployment works with any Proxmox VE 8 or 9 cluster, any Cloudflare account with Zero
Trust, and a Windows Server 2025 host for the broker. One file holds every value of your
deployment, and one command turns it into the exact ordered steps.

**AI agents:** read [AGENTS.md](AGENTS.md) first. It holds the rules and the workflow.

### Prerequisites

| Where | What you need |
|---|---|
| Proxmox VE | Root shell on one node (SSH). A resource pool for the guests the AI may see. |
| Broker host | Windows Server 2025, BitLocker with TPM, outbound HTTPS and UDP/TCP 7844, a route to the Proxmox API port. No inbound port. |
| Cloudflare | Zero Trust with an identity provider that enforces MFA, an MCP Server Portal, a zone for two host names, Workers (Standard plan), R2. An API token with the permissions in the header of `deploy/cloudflare/provision.sh`. |
| Azure (or equal) | A storage container with a locked time-based retention policy for the audit log. |
| Workstation | Python 3.11 or later, `uv`, Node 22, `jq`, `curl`, `openssl`, `ssh`. |
| Legal | If any guest in scope can hold PHI: signed BAAs with Cloudflare and Anthropic. |

### Steps

1. Copy the template and fill it. The copy is git-ignored. Put no secret in it.
   ```sh
   cp deploy/provision.example.toml deploy/provision.toml
   ```
2. Validate it and print the plan:
   ```sh
   python3 deploy/plan.py deploy/provision.toml            # numbered steps with exact commands
   python3 deploy/plan.py deploy/provision.toml --json     # the same plan for an AI agent
   ```
3. Run the steps in order. Each step names where it runs, who runs it, and the check
   that must pass before the next step:

   | Phase | Where | What |
   |---|---|---|
   | 0 preflight | you | Change approval, MFA policy, BAAs if PHI is in scope |
   | 1 build | workstation | Build the wheel, check the hashed lock, hash the downloads |
   | 2 proxmox | Proxmox node | Roles and pool, one user per person, read the TLS pin |
   | 3 broker | broker | Host baseline, broker install, cloudflared, firewall |
   | 4 credentials | node to broker | One API token per person, piped into DPAPI; enrollment |
   | 5 cloudflare | workstation | Tunnel, Access apps, Worker, R2 lock, portal entry |
   | 6 activate | broker | Second install pass with the Access values, key escrow, audit shipping |
   | 7 verify | broker and Claude | `Test-ProxmoxMcpBroker.ps1 -Live`, 401 check, first read from Claude |

4. Secrets never pass through a file, a chat or a command line. Proxmox tokens go from the
   node straight into the broker's DPAPI store. The Cloudflare API token is typed at a
   hidden prompt. The plan marks every such step `HUMAN, SECRET`.

[docs/RUNBOOK.md](docs/RUNBOOK.md) explains each step in detail, and covers day-2 tasks:
enroll a person, rotate a token, revoke access, emergency off.

## Architecture

The system has two parts on two sides of a trust boundary:

- The **Cloudflare Worker** (`worker/`) is the inbound gateway. It speaks MCP to
  Claude. It holds no Proxmox credential.
- The **broker** (this Python package) is the outbound gateway. It runs on an
  on-premises Windows Server host. It holds the Proxmox API tokens and makes the
  final policy decision.

```
Claude (claude.ai, Desktop, Code)
  |
  |  HTTPS, OAuth (Cloudflare Access Managed OAuth, Entra ID with MFA)
  v
Cloudflare MCP Server Portal + Access application (named users only)
  |
  v
Cloudflare Worker  https://<worker-hostname>/mcp
  |  - verifies the Access JWT again (RS256, team keys, issuer, audience)
  |  - JSON-RPC allowlist, size cap, per-user rate limit
  |  - 3 meta-tools: list_tools, describe_tool_input, execute_tool (MCP-STD-02)
  |  - signs an Ed25519 identity assertion for each broker call
  |  - redacts secrets and PHI patterns, labels results as untrusted data
  |
  |  Workers VPC binding, or Access service token, over a Cloudflare Tunnel
  v
cloudflared (Windows service, outbound connections only)
  |
  v
Broker  http://127.0.0.1:<port>   GET /healthz, GET /v1/catalog, POST /v1/execute
  |  - verifies the Access service-token JWT (the caller is the Worker)
  |  - verifies the identity assertion (signature, 60 s life, body hash, replay cache)
  |  - enrollment: user email -> mode (ro, operator, rw) and Proxmox token
  |  - tool policy, strict argument validation, rate limit
  |  - upstream tool handler
  |  - outbound policy: method and path allowlist per mode, deny list, PHI check
  |  - audit: one hash-chained JSON line per event, no argument values
  |
  |  HTTPS, TLS 1.2 or later, CA bundle or SHA-256 certificate pin
  v
Proxmox VE API  https://<proxmox-host>:8006   (one privilege-separated token per person)
```

The Proxmox API tokens never leave the broker host. Cloudflare holds no Proxmox
credential. The broker holds only the public half of the Worker signing key, so a
broker compromise cannot forge identities.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Security model

Each layer fails closed. A later layer does not trust an earlier layer.

| Layer | Control | Where |
|---|---|---|
| Person | Entra ID login with MFA. Access policy names each user. | Cloudflare Access |
| Session | Access token 10 min. OAuth session 8 h. Identity assertion 60 s. | Access, Worker |
| Gateway | JWT verified again, JSON-RPC allowlist, 256 KB cap, rate limit. | `worker/` |
| Broker entry | Service-token JWT, Host allowlist, no Origin, 256 KB cap. | `proxmox_mcp/transport/http_app.py` |
| Identity | Ed25519 assertion bound to body, method and path. Single use. | `proxmox_mcp/transport/identity_assertion.py` |
| Access list | `enrollment.json` maps each email to one mode and one token. | `proxmox_mcp/enrollment.py` |
| Tool policy | Every tool has a tier. Unknown tools are forbidden. | `proxmox_mcp/policy.py` |
| Arguments | Strict JSON Schema check. Path values have fixed patterns. | `proxmox_mcp/router.py` |
| Outbound | Method and path allowlist per mode. DELETE needs rw. Deny list for tokens, TFA, consoles, guest agent exec. | `proxmox_mcp/outbound.py` |
| PHI | Writes that contain PHI patterns are refused. Results are redacted. | `proxmox_mcp/phi.py`, `proxmox_mcp/output.py` |
| Proxmox | One privilege-separated API token per person. Proxmox ACLs limit each token. | Proxmox VE |
| TLS | Verified chain or SHA-256 pin. No redirects. No proxy settings from the environment. | `proxmox_mcp/client.py` |
| Output | Secret fields redacted. 2 MiB cap. Untrusted-data label on every result. | `proxmox_mcp/output.py` |
| Audit | Hash-chained JSONL with user, ray ID, tool, method, path, status. Keys and a hash of arguments, never values. | `proxmox_mcp/audit.py` |

Secrets are files, not environment variables. On Windows they are in the broker
credentials directory, protected by DPAPI and by an ACL for the service account.
On Linux they are systemd credentials.

Read [docs/SECURITY.md](docs/SECURITY.md) for the threat model and risk register.

## Modes and tool tiers

Each tool has one tier. Each enrolled person has one mode.

| Tier | Tools | What it covers |
|---|---|---|
| read | 133 | GET only: inventory, status, configuration, task logs. |
| operate | 16 | Reversible guest lifecycle: start, stop, shutdown, reboot, reset, suspend, resume, snapshot create. |
| admin | 85 | Guest create, clone, delete, configuration, disks, migration, guest firewall, pools, HA, backup jobs, SDN, raw host logs. |
| forbidden | 106 | Never available: users, tokens, ACLs, TFA, passwords, consoles, guest agent exec and files, cloud-init user data, host power and network, host disks, cluster firewall, certificates, storage definitions, notification endpoints. |

| Mode | Tiers | Tools |
|---|---|---|
| ro | read | 133 |
| operator | read, operate | 149 |
| rw | read, operate, admin | 234 when `MCP_ALLOW_ADMIN_TOOLS=1`, else 149 |

The default for every new person is `ro`. Admin tools stay off until the operator
sets `MCP_ALLOW_ADMIN_TOOLS=1` on the broker. `MCP_TOOL_DENY` and `MCP_TOOL_ALLOW`
can restrict the set more. They cannot add a tool.

## Compliance gate

This build is designed for HIPAA Security Rule and SOC 2 audits.

> **Go-live gate.** Protected health information (PHI) can pass through Cloudflare
> and Anthropic. Do not connect a system that holds PHI until a Business Associate
> Agreement (BAA) is signed with both Cloudflare and Anthropic.

The tools that read guest content are forbidden, and PHI patterns are redacted and
refused on writes. These controls reduce exposure. They do not replace the BAA.

Read [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for the control map and the evidence
that an auditor collects.

## Configuration

The broker reads its settings from environment variables and its secrets from the
credentials directory. [.env.example](.env.example) lists every setting with a
safe example value. Do not put a token or a password in `.env`.

The credentials directory contains:

| File | Content |
|---|---|
| `enrollment.json` | The access list: email, mode, Proxmox user ID, name of the token file. |
| `pve-token-<name>` | One line: `<user>@<realm>!<token-name>=<secret>`. One file per person. |
| `worker-identity.pub` | The Worker's Ed25519 public key (PEM). |

Example `enrollment.json`:

```json
{
  "users": {
    "alice@example.com": {
      "mode": "ro",
      "proxmox_userid": "mcp-alice@pve",
      "token_credential": "pve-token-alice"
    }
  }
}
```

Read [docs/RUNBOOK.md](docs/RUNBOOK.md) to install the broker, enroll a person,
rotate a token, and stop the service in an emergency.

## Local development

You can run the upstream stdio server on a workstation, against a lab cluster:

```sh
uv venv -p 3.14 .venv
uv pip install -p .venv -e . pytest pytest-asyncio ruff
export PROXMOX_HOST=pve.example.internal
export PROXMOX_TLS_FINGERPRINT=<sha256-of-the-proxmox-certificate>
export PROXMOX_USER=dev@pve PROXMOX_TOKEN_NAME=mcp
read -rs PROXMOX_TOKEN_VALUE && export PROXMOX_TOKEN_VALUE
.venv/bin/proxmox-mcp-server
```

The stdio server runs as the `local` identity. Its mode is `MCP_LOCAL_MODE`
(default `ro`). Use a lab token with few privileges. Do not use stdio mode on the
broker host.

## Tests

```sh
.venv/bin/pytest -q --no-cov
.venv/bin/ruff check proxmox_mcp tests
```

The tests run offline. The end-to-end tests (`tests/test_e2e_*.py`) start the real
broker application with a temporary credentials directory and drive it as the
Worker does. They execute every tool as `ro`, `operator` and `rw`, and check that:

- the decision agrees with the tool tier;
- a denied call never reaches Proxmox;
- an allowed call reaches Proxmox only with the caller's own token, and makes the
  same Proxmox calls as the upstream handler (`tests/fixtures/upstream_calls.json`);
- each result has the untrusted-data label, and secrets and PHI are redacted;
- the audit log has one line for each side, and the hash chain is intact.

`tests/test_e2e_tls.py` uses a real local TLS server with a pinned self-signed
certificate. With a wrong pin, no request byte reaches the server.

## Documents

| Document | Content |
|---|---|
| [AGENTS.md](AGENTS.md) | Rules and provisioning workflow for AI agents. |
| [deploy/provision.example.toml](deploy/provision.example.toml) | Template of every deployment value. |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data path, trust boundaries. |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model and risk register. |
| [docs/COMPLIANCE.md](docs/COMPLIANCE.md) | HIPAA and SOC 2 control map with evidence. |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Installation, operation, incident response. |
| [worker/README.md](worker/README.md) | The Cloudflare Worker. |
| [USAGE.md](USAGE.md) | How Claude finds and runs tools. |
| [CHANGELOG.md](CHANGELOG.md) | Changes by version. |

## Changes from upstream

- The tool handlers are unchanged, with one fix: `analyze_schedule` uses GET, as
  the Proxmox API defines it.
- Removed: password and ticket authentication, `PROXMOX_VERIFY_SSL`, one shared
  token for all users, and the stdio container as a deployment.
- Added: the broker HTTP API, identity assertions, enrollment, tool tiers,
  outbound policy, PHI filter, output redaction, the audit log and the
  `worker/` gateway.
- `setup.sh` and `test-connection.sh` no longer write or use secrets. They point
  to the runbook.
- `PROXMOX_READ_ONLY=true` still works. It is a kill switch for all writes on top
  of the modes.

## Credits and license

The Proxmox tools, their schemas and their handlers are the work of
[ry-ops](https://github.com/ry-ops) in
[proxmox-mcp-server](https://github.com/ry-ops/proxmox-mcp-server). Thank you.

MIT license. See [LICENSE](LICENSE). The copyright notice of ry-ops stays in
`LICENSE` and applies to the upstream code and to this fork.
