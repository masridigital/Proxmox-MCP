# Runbook: Proxmox MCP (Worker + Windows broker)

Use this runbook to install, operate and switch off the Proxmox MCP. All names are placeholders.
Run PowerShell scripts in an elevated Windows PowerShell 5.1 or PowerShell 7 on the broker,
started with `-NoProfile`. Run every PowerShell script with `-WhatIf` first. Run
`provision.sh` with `DRY_RUN=1` first.

Secret rules for operators: a secret goes only into a hidden prompt or through a pipe from
another program (ssh, a file redirect). Never type a secret as a literal in a command line or
a PowerShell pipeline (`'x' | ...`): it stays in PSReadLine history. Never use the clipboard
for a secret. Never run `provision.sh` with `bash -x` (it refuses).

Placeholders: `<worker-hostname>` (for example mcp.example.com), `<broker-hostname>` (access mode
only), `<proxmox-host>` (for example pve.example.internal), `<pool>`, `<short>` (user short name).

## 1. Install order

Do the steps in this order. Get a change approval first (SOC 2 CC8.1). Record the ticket number.

### 1.1 Build the release (build workstation)

1. Check out the approved commit. Run CI (lint, tests, pip-audit, npm audit, secret scan).
2. Build the wheel. The hashed runtime lock is `requirements/broker-win.txt` (generated from
   `uv.lock` by `requirements/generate_broker_lock.py`; CI checks it is current). Optional:
   download the wheels once into a wheelhouse for an offline install.
   ```
   uv build --wheel
   python requirements/generate_broker_lock.py --check
   pip download --require-hashes --no-deps --only-binary :all: --platform win_amd64 \
     --python-version <X.Y> -r requirements/broker-win.txt -d wheelhouse      # optional
   sha256sum dist/proxmox_mcp_server-*.whl requirements/broker-win.txt > SHA256SUMS
   ```
3. Python version. The first comment lines of `broker-win.txt` name the interpreter the hashes
   are for ("CPython X.Y"). The installer refuses any other major.minor. Use the newest
   python.org Windows installer of that X.Y. Today the lock says 3.12, and 3.12.10 is the last
   3.12 Windows installer (3.12 gets source-only security fixes since then). That is open risk
   T23 in docs/SECURITY.md: regenerate the lock for a CPython line that still ships Windows
   security builds before go-live (COMPLIANCE gate G10).
4. Download and record SHA-256 values for: the python.org installer, the cloudflared MSI
   (2025.7.0 or later), and WinSW v2.12.0 `WinSW.NET461.exe`. Confirm each hash from a second
   network. The installers copy each file into an Administrators-only staging folder and check
   the hash of that copy, which is the file that runs.

### 1.2 Proxmox (on a Proxmox node, as root)

1. Create the pool and put only the guests the AI may see into it.
2. Create the roles and the pool:
   ```
   MCP_POOL=<pool> DRY_RUN=1 ./setup-proxmox-access.sh roles
   MCP_POOL=<pool> ./setup-proxmox-access.sh roles
   ```

### 1.3 Broker host baseline (Windows Server 2025)

1. Join the management domain or apply local policy. Apply the hardening checklist (section 9).
2. Run `Set-BrokerHostBaseline.ps1 -WhatIf`, then without `-WhatIf`. Reboot.

### 1.4 Broker software

1. Copy `deploy\windows\*` and the build artifacts to the broker.
2. Install:
   ```
   .\Install-ProxmoxMcpBroker.ps1 -PythonInstaller .\python-<X.Y.Z>-amd64.exe -PythonSha256 <hex> `
     -WheelPath .\proxmox_mcp_server-<v>-py3-none-any.whl -WheelSha256 <hex> `
     -RequirementsLock .\broker-win.txt -RequirementsLockSha256 <hex> [-Wheelhouse .\wheelhouse] `
     -WinSWPath .\WinSW.NET461.exe -ProxmoxHost <proxmox-host> -ProxmoxTlsFingerprint <sha256> `
     -BrokerMode vpc -WhatIf
   ```
   Then run it again without `-WhatIf`. The installer validates `broker.env` with the broker's
   own parser (`proxmox_mcp.config.load(role="broker")`) before it writes it or touches the
   service. Never edit `broker.env` by hand: unknown or malformed `PROXMOX_*`, `MCP_*`,
   `BROKER_*` and `CF_ACCESS_*` variables stop the broker, and booleans must be exactly 0 or 1. In access mode add `-BrokerMode access -BrokerHostHeader
   <broker-hostname> -CfAccessTeamDomain https://<team>.cloudflareaccess.com -BrokerAccessAud <aud>
   -BrokerServiceClientIds <client id>` (values come from `provision.sh`).
3. Install cloudflared:
   ```
   .\Install-Cloudflared.ps1 -MsiPath .\cloudflared-windows-amd64.msi -MsiSha256 <hex> -Version <version>
   ```
4. Firewall:
   ```
   .\Set-BrokerFirewall.ps1 -ProxmoxAddress <proxmox-ip>/32 -WhatIf
   .\Set-BrokerFirewall.ps1 -ProxmoxAddress <proxmox-ip>/32
   ```
   Access mode: add `-BrokerMode access -FetchCloudflareRanges`. A re-run adds the new rule
   generation before it removes the old one, so there is no moment without block rules.
5. Escrow the audit key with two custodians: docs/COMPLIANCE.md section 7.
6. Schedule the selfcheck (CC6.3 evidence): `.\Invoke-BrokerSelfCheck.ps1 -Register`.

### 1.5 Cloudflare (admin workstation)

1. Create an API token with the permissions listed in the header of `provision.sh`.
2. Deploy the Worker once so it exists (it fails closed without secrets).
3. Run the provisioning, dry run first:
   ```
   export ACCOUNT_ID=<id> ZONE_ID=<id> WORKER_HOSTNAME=<worker-hostname> TEAM_DOMAIN=https://<team>.cloudflareaccess.com \
          IDP_ID=<entra idp id> ALLOWED_EMAILS=alice@example.com PORTAL_ID=<portal id> SERVER_ID=proxmox \
          WORKER_DIR=./worker AUDIT_BUCKET=<bucket> BROKER_SSH=<admin>@<broker> BROKER_MODE=vpc
   read -r -s CF_API_TOKEN; export CF_API_TOKEN   # the script un-exports it at once
   DRY_RUN=1 ./deploy/cloudflare/provision.sh
   ./deploy/cloudflare/provision.sh
   STEPS=worker DEPLOY_WORKER=1 ./deploy/cloudflare/provision.sh
   ```
   The script creates the tunnel, the VPC Service (or the fallback app, token and DNS), the
   Worker Access app and policy, the R2 bucket lock, the identity key, the portal entry, and
   delivers the tunnel token and the Worker public key to the broker over SSH
   (`powershell.exe -NoProfile -NonInteractive -File ...`; set `BROKER_PS=pwsh` for PowerShell 7).
   Order matters and is enforced: an Access app and its policy exist before any DNS record or
   Worker deploy. The Worker deploy is refused unless the Worker Access app passes the policy
   checks (named users, Entra login, MFA unless `REQUIRE_MFA=0`).
4. The rendered config is `worker/.wrangler/proxmox-mcp-deploy/wrangler.deploy.jsonc`
   (git-ignored; the script refuses a path git would track). It holds account ids. Never
   commit it.

### 1.6 Audit shipping

1. Create an Azure storage container with a time-based retention policy of 2190 days. Lock it.
2. Create a container SAS with permission `c` only, HTTPS only, expiry of one year or less.
3. On the broker:
   ```
   .\Send-AuditLog.ps1 -Register -StorageAccount <account> -Container <container>
   .\Protect-BrokerCredential.ps1 -Name audit-ship-sas -Reader System    # paste at the hidden prompt
   .\Send-AuditLog.ps1 -TestImmutability -AdminCheck
   ```
   The SAS must be `sp=c` only, `spr=https`, with `se=` at most one year away (the script
   refuses anything else). Event 4106 warns 30 days before expiry.
   The test must show 409 (or 403) for overwrite and delete with the ship credential, and
   `BlobImmutableDueToPolicy` for overwrite and delete with the admin identity.

### 1.7 Go-live checks

1. Enroll at least one user (section 2).
2. `.\Test-ProxmoxMcpBroker.ps1 -Baseline -Live` shows no FAIL (it runs `proxmox-mcp-selfcheck --live`).
3. `STEPS=verify ./deploy/cloudflare/provision.sh` passes.
4. In Claude: add the connector, sign in, run one read. Check the audit line on the broker.
5. Confirm the BAA gate in docs/COMPLIANCE.md section 1.

## 2. Enroll a user

1. Add the email to `ALLOWED_EMAILS` and run `STEPS=access ./deploy/cloudflare/provision.sh`.
2. Issue the token and store it on the broker in one pipe. The secret is never on disk:
   ```
   ssh root@<proxmox-host> 'MCP_POOL=<pool> bash -s -- issue-token <short> ro' < deploy/proxmox/setup-proxmox-access.sh \
     | ssh <admin>@<broker> "powershell.exe -NoProfile -NonInteractive -File 'C:\Program Files\ProxmoxMCP\scripts\Protect-BrokerCredential.ps1' -Name pve-token-<short>"
   ```
   The Proxmox script prints `token_expires=<YYYY-MM-DD>` on stderr. The user expires on the same
   date as the token.
3. Enroll on the broker (validated with the broker's parser before it replaces the file; one
   person, one Proxmox user, one token):
   ```
   .\Set-BrokerEnrollment.ps1 -Email <email> -Mode ro -ProxmoxUserId mcp-<short>@pve -TokenExpires <YYYY-MM-DD>
   Restart-Service ProxmoxMCPBroker
   .\Invoke-BrokerSelfCheck.ps1 -Live
   ```
   If the installed broker does not accept `token_expires` in enrollment.json yet, the script
   keeps the date in `config\token-expiry.json` and says so.
4. Modes: `ro` (default), `operator` (power and snapshot), `rw` (admin tier only when
   `MCP_ALLOW_ADMIN_TOOLS=1`). Use the same mode in steps 2 and 3.

## 3. Rotate

| Secret | Command | Interval |
|---|---|---|
| Proxmox token of a user | Step 2.2 with `ROTATE=1` in the remote environment and `-Force` on Protect-BrokerCredential, then `Set-BrokerEnrollment.ps1 ... -TokenExpires <new date>` and restart the broker | 90 days (token expiry; selfcheck warns 14 days before) |
| Worker identity key | `ROTATE_IDENTITY_KEY=1 STEPS="identity worker" DEPLOY_WORKER=1 ./provision.sh` | Yearly or on suspicion |
| Access service token (access mode) | `ROTATE_SERVICE_TOKEN=1 STEPS=broker ./provision.sh` | Yearly or on suspicion |
| Tunnel token | Cloudflare dashboard or API: rotate the tunnel secret, then `STEPS=token ./provision.sh` | On suspicion |
| Audit SAS | New SAS (sp=c), then `Protect-BrokerCredential.ps1 -Name audit-ship-sas -Reader System -Force` | Before expiry (event 4106) |
| Audit HMAC key | docs/COMPLIANCE.md section 7.4 (re-key and two-person escrow) | On custodian change or suspicion |

Proxmox VE 9.1 and later regenerate a token in place and keep its ACLs. Older versions delete
and recreate the token; the script reapplies the ACLs.

## 4. Revoke one user

1. Remove the email from `ALLOWED_EMAILS`; run `STEPS=access ./provision.sh`.
2. In Cloudflare Zero Trust, revoke the user's sessions.
3. `.\Set-BrokerEnrollment.ps1 -Email <email> -Remove`, then restart the broker.
4. `ssh root@<proxmox-host> 'bash -s -- revoke <short>' < deploy/proxmox/setup-proxmox-access.sh`
5. Delete `pve-token-<short>.dpapi` on the broker.

## 5. Emergency off (any one step stops all use; do all three for an incident)

| Step | Effect | Command |
|---|---|---|
| 1. Access off | No new sign-ins or tokens | Zero Trust > Access > Applications > `<worker-hostname>` > disable the policy, or set it to deny. Revoke all sessions. |
| 2. Tunnel off | Worker cannot reach the broker | On the broker: `Stop-Service cloudflared-proxmox-mcp; Set-Service cloudflared-proxmox-mcp -StartupType Disabled`. From the admin workstation: `STEPS=off ./provision.sh` (vpc: deletes the VPC service; access: deletes the broker DNS record and sets ingress to 404). |
| 3. Proxmox tokens off | No API access even with the broker | `ssh root@<proxmox-host> 'bash -s -- revoke-all' < deploy/proxmox/setup-proxmox-access.sh` |

Also stop the broker: `Stop-Service ProxmoxMCPBroker`. Keep the audit files. Run
`Send-AuditLog.ps1` once by hand to ship the last bytes.

## 6. Upgrade

1. Change approval. Build the new wheel and lock (section 1.1).
2. On the broker: run `Install-ProxmoxMcpBroker.ps1` with the new files and `-WhatIf`, then
   without. It builds a new venv under `C:\Program Files\ProxmoxMCP\venvs\<id>` while the old
   version keeps running, checks it (entry points, `pip check`, the broker's config parser), and
   only then switches the service. If the new version does not stay running, it switches back
   to the previous venv by itself. `broker.env` and the credentials are kept.
3. `.\Test-ProxmoxMcpBroker.ps1 -Live`.
4. Rollback: `.\Install-ProxmoxMcpBroker.ps1 -Rollback -WhatIf`, then without `-WhatIf`. It
   points the service at the previous venv recorded in `installed.json`. A Python minor-version
   change makes earlier venvs unusable; roll back by reinstalling the earlier release then.
5. cloudflared: run `Install-Cloudflared.ps1` with the new MSI, hash and version. Keep it at most
   one month behind the latest release.
6. Worker: deploy from the approved commit with `STEPS=worker DEPLOY_WORKER=1`. Rollback with
   `wrangler rollback`.

## 7. Audit verify

| Check | Command | Expect |
|---|---|---|
| Local chain (keyed) | `.\Test-ProxmoxMcpBroker.ps1` (runs `proxmox-mcp-audit-verify --dir C:\ProgramData\ProxmoxMCP\logs --require-mac` with the broker credentials) | PASS, exit 0 |
| Anchors | The shipper stores the verify summary (last seq and hash) under `<prefix>/<host>/anchors/` after each upload | One anchor per shipping run with new data |
| Shipping health | Event Viewer > Application > source `ProxmoxMCP-AuditShip`: 4001 every 5 min; 4101/4102/4103 are errors | No errors |
| WORM | `.\Send-AuditLog.ps1 -TestImmutability -AdminCheck` | pass = true |
| Shipped copy | `az storage blob list ... --include m -o json > blobs.json`; `az storage blob download-batch ...`; `.\Test-ShippedAudit.ps1 -BlobListJson blobs.json -DownloadDir dl -KeyFile <escrowed key> -Anchor <seq>:<hash> -VerifyExe <verify exe>` | exit 0 |
| Worker audit (R2) | Use the Worker's verify procedure (see worker/README) | 0 breaks |

### 7.1 Escrow the audit key

Two-person procedure, `Export-AuditKeyEscrow.ps1`: docs/COMPLIANCE.md section 7. Never copy
the key through the clipboard, a chat or a ticket.

## 8. Monitoring

### 8.1 Uptime check (external)

Every 5 minutes, from outside: `POST https://<worker-hostname>/mcp` with a JSON-RPC `initialize`
body and no credentials. Expect HTTP 401 with a `WWW-Authenticate` header. Any other status
(200, 404, 5xx, 530) is an alert. `STEPS=verify ./provision.sh` runs the same check.

### 8.2 Alert conditions

| Alert | Source | Condition | Severity |
|---|---|---|---|
| Service down | Broker: Windows events 7031/7034 for `ProxmoxMCPBroker` or `cloudflared-proxmox-mcp`; `Test-ProxmoxMcpBroker.ps1` exit 1 (scheduled hourly) | Any | High |
| Tunnel down | Cloudflare tunnel health notification; `http://127.0.0.1:20241/ready` not 200 | 5 min | High |
| Uptime | 8.1 | 2 failures in a row | High |
| Auth failures | Broker audit `kind` deny with assertion or JWT reason; Access logs denied logins | More than 10 in 10 min | Medium |
| Denied bursts | Broker audit deny (policy, outbound, rate) per user | More than 20 in 10 min for one user | Medium |
| Chain break | `proxmox-mcp-audit-verify` non-zero; event 4101 (file shrank) | Any | High |
| Shipping failed | Events 4102 or no 4001 for 15 min | Any | High |
| Immutability test failed | Event 4103 | Any | High |
| Token near expiry | Selfcheck event 4202 (`token_expiry` warn); access review finding | Any | Low |
| Least privilege drift | Selfcheck event 4203 (a token holds a privilege outside its mode, shared token, root@pam) | Any | High |
| Selfcheck did not run | Event 4204, or no 4201/4202/4203 for 26 h | Any | High |
| Audit SAS near expiry | Event 4106 | Any | Medium |
| cloudflared outdated | Installed version older than 1 month | Any | Low |

Send Windows events to the SIEM with Azure Monitor Agent or Windows Event Forwarding.
Send Cloudflare Access and Workers logs with Logpush (covered by the Cloudflare BAA).

## 9. Windows hardening checklist (broker)

| Item | Required | How to check |
|---|---|---|
| BitLocker on all volumes, TPM protector, recovery key escrowed | Yes | `Get-BitLockerVolume` |
| Microsoft Defender on, tamper protection, signatures under 2 days | Yes | `Get-MpComputerStatus` |
| Windows LAPS manages the local Administrator password | Yes | `Get-LapsDiagnostics` or policy registry |
| Audit policy: process creation (with command line), logon, logoff, special logon, lockout, credential validation, group management, policy change, file system | Yes | `auditpol /get /category:*` |
| PowerShell script block logging | Yes | registry, Test script |
| LSA protection (RunAsPPL) | Yes | Test script |
| Credential Guard | Yes, where hardware supports VBS | `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard` |
| SMBv1 off | Yes | `Get-SmbServerConfiguration` |
| RDP off, or NLA and only from the management network; never from the internet | Yes | Test script, perimeter firewall |
| WDAC (preferred) or AppLocker: allow the private `python.exe`, `pythonw.exe`, the venv launchers, `WinSW` (hash rule, unsigned), cloudflared (publisher rule "Cloudflare, Inc.") | Recommended | `Get-CIPolicy` / `Get-AppLockerPolicy -Effective` |
| Windows Update monthly, reboot window agreed | Yes | `Get-HotFix` |
| No other workloads, no browsers used on the server | Yes | Inventory |
| Admin access through a privileged access workstation | Recommended | Policy |

## 10. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Portal or Claude shows HTTP 530 with error 1016 | The MCP server hostname has no working origin. Worker custom domain not deployed, or (access mode) the broker CNAME points to a tunnel that does not exist in the account. | Deploy the Worker (`STEPS=worker DEPLOY_WORKER=1`). Check DNS: the record must be proxied and point to `<tunnel-id>.cfargotunnel.com` of this account. Re-run `STEPS=broker`. |
| HTTP 530 with error 1033 (access mode) | Tunnel has no connected connector | On the broker: `Get-Service cloudflared-proxmox-mcp`; read `C:\ProgramData\ProxmoxMCP\cloudflared\logs\cloudflared.log`; check UDP/TCP 7844 egress. |
| Worker gets `dns_error` or fetch exceptions to `broker.internal` (vpc mode) | cloudflared older than 2025.7.0, or QUIC blocked (fell back to HTTP/2) | Upgrade cloudflared; keep `--protocol quic`; allow UDP 7844 outbound. |
| Claude: "Couldn't determine how this server signs in" | `/mcp` does not answer 401 with `WWW-Authenticate` | Run `STEPS=verify`. Check the Access app has `oauth_configuration.enabled=true`. |
| Sign-in loops or "access denied" | User not in the policy, or not signed in with Entra | Check `ALLOWED_EMAILS`; check the Access login log. |
| Every tool call fails with "not enrolled" | Email missing from `enrollment.json` or file invalid | `.\Set-BrokerEnrollment.ps1 -List`; check the service error log. |
| Broker service stops at once (exit code 2) | Configuration error: an unknown or malformed `PROXMOX_*`/`MCP_*`/`BROKER_*`/`CF_ACCESS_*` variable, a boolean that is not exactly 0 or 1, missing `CF_ACCESS_*` or `BROKER_ALLOWED_SERVICE_CLIENT_IDS` in access mode, `worker-identity.pub` missing or not Ed25519, or `audit-hmac.key` missing (`MCP_AUDIT_HMAC=required`) | Read `C:\ProgramData\ProxmoxMCP\logs\service\ProxmoxMCPBroker.err.log` (it names variables, never values). Fix `broker.env` with the installer, or store the key. |
| Installer stops with "does not match the lock" | Python installer major.minor differs from the `CPython X.Y` line of `broker-win.txt` | Use the matching installer, or regenerate the lock (SECURITY.md T23). |
| Installer stops with "owned by" or "junction" | A folder under `C:\ProgramData\ProxmoxMCP` was created by another account, or is a link | Treat as a security incident: find who created it (Security log 4663 / 4656), then delete it and re-run. |
| Broker calls to Proxmox time out | Firewall program rule targets the wrong `python.exe`, or the Proxmox address changed | `Get-NetFirewallRule -Group ProxmoxMCP`; re-run `Set-BrokerFirewall.ps1`. |
| TLS error to Proxmox | Proxmox certificate renewed; pin is stale | Get the new SHA-256 fingerprint on the node (`pvenode cert info`), re-run the installer with `-ProxmoxTlsFingerprint`. |
| Portal sync fails | The portal server needs an admin OAuth sign-in first | Sign in to the server in the portal, then `STEPS=portal`. |
| `Send-AuditLog.ps1` HTTP 403 | SAS expired or wrong permissions | Issue a new `sp=c` SAS and store it. |
