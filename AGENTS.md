# AGENTS.md: instructions for AI agents

This file tells an AI agent (Claude Code, Codex, Cursor or similar) how to provision and
change this repository safely. People can use it too. It is the contract; the README is
the overview.

## What you are provisioning

```
Claude -> Cloudflare MCP portal -> Cloudflare Access (named users, MFA)
       -> Cloudflare Worker (worker/)  -> private link -> Windows broker (proxmox_mcp/)
       -> Proxmox VE API (one privilege-separated token per person)
```

Three places get configuration: the **Proxmox node**, the **Windows Server broker** and
**Cloudflare**. The single source of every value is one file:
`deploy/provision.toml` (copy of `deploy/provision.example.toml`, git-ignored).

## Hard rules

1. **No organization data in the repository.** Never commit `deploy/provision.toml`, real
   host names, IP addresses, account or zone ids, AUD tags, IdP ids, emails, VM names,
   tunnel ids or state files. Examples use `example.com`, `example.internal` and
   `192.0.2.0/24` only. Before every commit, run:
   `git grep -nIE '<each real value you used>'` and expect no output.
2. **Never handle a secret.** Do not ask the user for a secret, do not type one, do not
   run a step whose plan entry has `"secret": true`, and do not read its output. Secrets
   are: Proxmox API tokens, the Cloudflare API token, the tunnel token, the Access
   service-token secret, the Worker signing key, the audit HMAC key and the Azure SAS.
   They go from host to host through pipes or hidden prompts only. Give the user the
   exact command and wait for "done".
3. **Ask before outward-facing changes.** Creating Cloudflare objects, changing DNS,
   changing Proxmox ACLs or installing on the broker changes real systems. Show the plan
   step, get a yes, then run it. Always run the `-WhatIf` / `DRY_RUN=1` form first.
4. **Never weaken a control to make a step pass.** Do not set `PROXMOX_INSECURE_TLS`,
   `MCP_ALLOW_NON_LOOPBACK`, `MCP_ALLOW_SERVICE_TOKENS`, `BROKER_REQUIRE_ACCESS_JWT=0`
   (outside vpc mode), `REQUIRE_MFA=0` or `MCP_ALLOW_ADMIN_TOOLS=1` unless the user asks
   for it in so many words, and record the decision. Never enroll `root@pam`. Never run
   `provision.sh` with `bash -x`.
5. **Fail closed, report plainly.** If a verify line in the plan fails, stop. Report the
   command, the output and the cause. Do not continue to the next phase.

## Provisioning workflow

1. **Collect values.** Ask the user for the values below (one short question per group).
   Write them to `deploy/provision.toml`. Never write secrets there.

   | Ask | Keys in `provision.toml` |
   |---|---|
   | Proxmox node, port, SSH target, pool name | `[proxmox] host port ssh pool` |
   | Broker host, optional SSH target, Proxmox CIDRs for the firewall | `[broker] hostname ssh proxmox_addresses` |
   | Cloudflare account, zone, team domain, IdP id, portal id | `[cloudflare] account_id zone_id team_domain idp_id portal_id` |
   | Worker hostname and (access mode) broker hostname | `[cloudflare] worker_hostname broker_hostname` |
   | Access path to the broker: `access` (GA) or `vpc` (beta) | `[deployment] broker_mode` |
   | People: email, short name, mode (`ro` by default) | `[[users]]` |
   | Can a guest in scope hold PHI? If yes, the BAA dates | `[deployment] phi_in_scope baa_*` |
   | Azure storage account and container for audit shipping | `[audit_shipping]` |
   | Two audit-key custodians (not broker admins) | `[escrow]` |
   | Artifact hashes (Python installer, cloudflared MSI, WinSW) | `[artifacts]` |

   If the user has a Cloudflare or RMM integration available to you, you may look up
   non-secret ids (account, zone, IdP, portal) read-only instead of asking.

2. **Validate and plan.**
   ```sh
   python3 deploy/plan.py deploy/provision.toml          # must exit 0
   python3 deploy/plan.py deploy/provision.toml --json   # read this; it is your task list
   ```
   Each step has `id`, `phase`, `where` (mac, proxmox, broker, cloudflare, claude),
   `runner` (`agent` or `human`), `secret`, `commands` and `verify`.

3. **Execute in order.** For each step:
   - `runner: agent` and you have an approved shell on `where`: show the commands, get a
     yes, run the dry run, then the real command, then check `verify`.
   - `runner: agent` and you have no shell there: give the user the commands to run and
     ask for the output of the verify check.
   - `runner: human` or `secret: true`: give the user the exact commands. Wait for
     "done". Do not ask for the output of secret steps.
   - `proxmox-pin`: write the result to `[proxmox] tls_fingerprint`, then run the plan
     again (later commands use it).
   - `cloudflare`: afterwards you may read `~/.proxmox-mcp/<worker_hostname>.json`
     (ids only) to fill the `<broker_aud>` and `<service_token_client_id>` values of
     step `broker-activate`.

4. **Go-live gate.** Run step `verify`. Then the user connects Claude (step `connect`).
   Do not call the deployment live until both pass and the gates in step `gates` are
   recorded.

## Day-2 tasks

| Task | How |
|---|---|
| Add a person | Add a `[[users]]` block, run the plan, run that user's `proxmox-user-*`, `token-*` and `enroll-*` steps, re-run step `cloudflare` (adds the email to the Access policy). |
| Rotate a token | `ROTATE=1` on the `token-*` command, then the `enroll-*` step with the new date. |
| Change a mode | Edit `mode`, re-run the user's three steps. `rw` also needs `[broker] allow_admin_tools = true`. |
| Remove a person | `ssh <node> 'bash -s -- revoke <short>' < deploy/proxmox/setup-proxmox-access.sh`, then `Set-BrokerEnrollment.ps1 -Email <email> -Remove`, then remove the block and re-run step `cloudflare`. |
| Emergency off | `STEPS=off ./deploy/cloudflare/provision.sh`; stop the broker services; `revoke-all` on the node. See docs/RUNBOOK.md. |

## Changing the code

- Python 3.12 or later. `uv venv -p 3.14 .venv && uv pip install -p .venv -e . pytest pytest-asyncio pytest-cov ruff`.
- Before every commit: `.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/pytest -q --no-cov`.
  Worker: `cd worker && npm ci --ignore-scripts && npm run typecheck && npm test`.
- Every tool has an explicit tier in `proxmox_mcp/policy.py`; a new tool without one is
  forbidden and fails the tests. Every Proxmox path must be in `proxmox_mcp/outbound.py`.
- A fix to a security control comes with a test that fails on the old code.
- Docs use Simplified Technical English: short sentences, active voice, no em dashes.

## Map

| Path | What |
|---|---|
| `deploy/provision.example.toml` | Template of every deployment value |
| `deploy/plan.py` | Validates the file and prints the ordered plan (text, JSON, env) |
| `deploy/proxmox/setup-proxmox-access.sh` | Proxmox roles, users, tokens, revoke |
| `deploy/windows/*.ps1` | Broker install, firewall, credentials, enrollment, audit, tests |
| `deploy/cloudflare/provision.sh` | Tunnel, Access apps, Worker, R2 lock, portal, verify |
| `proxmox_mcp/` | The broker (upstream tools plus the security layers) |
| `worker/` | The Cloudflare Worker (MCP gateway) |
| `docs/` | Architecture, security risk register, compliance map, runbook |
