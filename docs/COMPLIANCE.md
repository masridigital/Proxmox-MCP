# Compliance: HIPAA Security Rule and SOC 2 control matrix

This document maps the HIPAA Security Rule (45 CFR 164.308, 164.310, 164.312, 164.316) and the
SOC 2 Trust Services Criteria (2017, revised points of focus 2022: CC1 to CC9, A1, C1) to the
controls of this build. For each control it names the file or configuration that implements it
and the evidence an auditor collects.

Scope: the Proxmox MCP data path (Claude, Cloudflare Access and Worker, Windows broker,
Proxmox VE API). Organization-wide controls (HR, training, vendor program, physical sites) are
inherited from the entity's own program and are marked "entity".

Commands run on the broker in an elevated PowerShell unless they say otherwise. `<...>` values
are placeholders.

## 1. Go-live gates (all must be true before PHI can transit)

| Gate | Requirement | Evidence |
|---|---|---|
| G1 | Signed BAA with Cloudflare. The Cloudflare BAA is available on the Enterprise plan. It must cover Access, Workers, Workers Logs and Logpush, R2, Tunnel and Workers VPC. | BAA copy and plan confirmation in the vendor file |
| G2 | Signed BAA with Anthropic for the Claude plan in use (claude.ai Enterprise or API terms that include a BAA). | BAA copy in the vendor file |
| G3 | Risk analysis reviewed and accepted (docs/SECURITY.md) | Signed review log entry |
| G4 | All tests in docs/RUNBOOK.md section 1.7 pass | `Test-ProxmoxMcpBroker.ps1 -Baseline` output, `provision.sh STEPS=verify` output |
| G5 | WORM test passes | `ship\immutability-test-*.json` with `pass: true` |
| G6 | First access review done | `evidence\access-review-<date>\SHA256SUMS.txt` hash in the ticket |

Until G1 and G2 are true, the build may run only against Proxmox guests that hold no PHI, and
nobody may put PHI in guest names, notes, descriptions or tags.

## 2. PHI minimization (164.502(b) minimum necessary)

The build keeps PHI out of the data path by design. It does not depend on the redaction filter.

| Measure | Implementation |
|---|---|
| Guest content is never read | Tools for guest agent exec, file read and write, user lists, console and shells (termproxy, VNC, SPICE) are in the forbidden tier (`proxmox_mcp/policy.py`). Proxmox roles exclude `VM.GuestAgent.*`, `VM.Console` and `VM.Config.Cloudinit` (`deploy/proxmox/setup-proxmox-access.sh`). |
| Only one pool is visible | ACLs on `/pool/<pool>` only |
| Read-only by default | Mode `ro` is the default; admin tier needs `rw` and `MCP_ALLOW_ADMIN_TOOLS=1` |
| PHI patterns redacted in output, refused in writes | `proxmox_mcp/output.py`, `proxmox_mcp/phi.py` (broker); the Worker repeats the redaction |
| Audit holds no values | Argument keys and SHA-256 of canonical arguments only |
| Policy | Guest names, notes, descriptions and tags must not contain PHI (acceptable use statement for enrolled users) |

## 3. HIPAA Security Rule matrix

| Citation | Requirement | Control | Implemented in | Evidence |
|---|---|---|---|---|
| 164.308(a)(1)(ii)(A) | Risk analysis | Threat model and risk register with likelihood, impact, residual | docs/SECURITY.md | Document with review log |
| 164.308(a)(1)(ii)(B) | Risk management | Controls in this matrix; residual risks accepted by owner | docs/SECURITY.md, this file | Signed acceptance |
| 164.308(a)(1)(ii)(D) | Information system activity review | Monthly review of broker audit denies, Access logs, alert history | RUNBOOK section 8 | Review ticket with query output |
| 164.308(a)(3)(ii)(B), (C) | Workforce clearance, termination | Enrollment only by change ticket; revoke procedure | `Set-BrokerEnrollment.ps1`, RUNBOOK section 4 | Ticket + `Set-BrokerEnrollment.ps1 -List` before/after |
| 164.308(a)(4)(ii)(B), (C) | Access authorization, establishment and modification | Named-user Access policy; enrollment modes; pool-scoped Proxmox roles | `provision.sh` (access step), `enrollment.json`, `setup-proxmox-access.sh` | `Export-AccessReview.ps1` folder |
| 164.308(a)(5)(ii)(C) | Log-in monitoring | Access login logs; broker auth-failure alerts | RUNBOOK 8.2 | Alert configuration export, Access log export |
| 164.308(a)(5)(ii)(D) | Password management | No passwords: Entra SSO with MFA; Proxmox users have no password; tokens expire in 90 days | `setup-proxmox-access.sh` | `pveum user list` (no password), token expiry in access review |
| 164.308(a)(6)(ii) | Security incident procedures | Emergency off (three independent switches), alerting, evidence preservation | RUNBOOK sections 5 and 8 | Incident drill record (yearly) |
| 164.308(a)(7)(ii)(A), (B) | Data backup and disaster recovery | Broker is rebuildable from repo + build artifacts; config backup (not tokens); RTO/RPO in section 6 | RUNBOOK section 1, this file section 6 | Restore drill record |
| 164.308(a)(8) | Evaluation | Yearly review of this matrix; after every architecture change | This file | Review log |
| 164.308(b)(1), 164.314(a) | Business associate contracts | Go-live gates G1, G2 | Section 1 | BAA copies |
| 164.310(a)(1) | Facility access | Broker in a controlled site or data center | entity | Facility policy |
| 164.310(d)(1) | Device and media controls | BitLocker with TPM on all broker volumes; DPAPI secrets useless off the host | `Set-BrokerHostBaseline.ps1`, `Test-ProxmoxMcpBroker.ps1 -Baseline` | Test output (BitLocker row) |
| 164.312(a)(1) | Access control | Access policy, enrollment, tool tiers, outbound allowlist, Proxmox roles | Worker, `proxmox_mcp/policy.py`, `outbound.py`, `setup-proxmox-access.sh` | Access review folder; `pveum user permissions mcp-<short>@pve` |
| 164.312(a)(2)(i) | Unique user identification | One Access identity per person, one Proxmox user and token per person; email on every audit line (Worker and broker) | `enrollment.json`, audit | Sample audit lines; Proxmox task log shows `mcp-<short>@pve` |
| 164.312(a)(2)(ii) | Emergency access procedure | Proxmox admins keep direct GUI access outside the MCP; MCP emergency off | RUNBOOK section 5 | Procedure + drill record |
| 164.312(a)(2)(iii) | Automatic logoff | Access token 10 min; Access session and OAuth grant 8 h; identity assertion 60 s | `provision.sh` (`SESSION_DURATION=8h`, `ACCESS_TOKEN_LIFETIME=10m`) | `cloudflare-access.json` in the access review (session_duration, oauth_configuration.grant) |
| 164.312(a)(2)(iv) | Encryption and decryption | BitLocker (TPM); DPAPI for secrets; Worker secrets encrypted by Cloudflare | Baseline, `Protect-BrokerCredential.ps1` | Test output; `Get-ChildItem credentials` shows `*.dpapi` only |
| 164.312(b) | Audit controls | Broker hash-chained JSONL; Worker AuditChain to R2; Workers Logs; Windows Security log (process creation, logon); Cloudflare audit logs | `audit.py`, Worker, `Send-AuditLog.ps1`, baseline | `proxmox-mcp-audit-verify` output; shipped blobs listing |
| 164.312(c)(1), (c)(2) | Integrity, mechanism to authenticate | Keyed hash chain (`ph`, `seq`, HMAC `mac` with `audit-hmac.key`, `MCP_AUDIT_HMAC=required`); verify summary anchors stored in WORM after each upload; chunk SHA-256 and `prevsha256` chain in blob metadata; Azure locked immutability 2190 days; R2 bucket lock; SACL on the log directory | `Send-AuditLog.ps1`, `Test-ShippedAudit.ps1`, `provision.sh` (r2) | Immutability test JSON; `Test-ShippedAudit.ps1` output; `az storage container immutability-policy show` |
| 164.312(d) | Person or entity authentication | Entra with MFA through Conditional Access; Access `require login_method`; broker accepts only Worker-signed assertions | `provision.sh`, `identity_assertion.py` | Access policy JSON; Entra CA policy export |
| 164.312(e)(1), (e)(2)(i), (ii) | Transmission security, integrity, encryption | TLS 1.2+ at the edge; tunnel (TLS/QUIC); TLS pinned to Proxmox; only loopback is plaintext | `cloudflared-proxmox-mcp` service, `broker.env` (`PROXMOX_TLS_FINGERPRINT`) | `broker.env`; `Test-ProxmoxMcpBroker.ps1` listener row |
| 164.316(a) | Policies and procedures | This file, SECURITY.md, RUNBOOK.md, ARCHITECTURE.md in version control | repo | Git history |
| 164.316(b)(1) | Documentation | Same, plus change tickets | repo | Git log, tickets |
| 164.316(b)(2)(i) | Retention 6 years | Azure Blob time-based retention 2190 days (locked); R2 bucket lock rule `hipaa-retention-6y` (Age 2190 days); documents kept 6 years in git | `Send-AuditLog.ps1`, `provision.sh` (r2) | `az storage container immutability-policy show`; `GET /accounts/<id>/r2/buckets/<bucket>/lock` |
| 164.316(b)(2)(iii) | Updates | Yearly review and after changes | This file | Review log |

## 4. SOC 2 matrix

| Criterion | Control | Implemented in | Evidence |
|---|---|---|---|
| CC1.1 to CC1.5 | Control environment | entity | Entity SOC 2 package |
| CC2.1 | Quality information for controls | Hash-chained audit with correlation ids (Cf-Ray, jti); version and catalog hash in the broker start event | `audit.py` | Start event sample |
| CC2.2 | Internal communication | RUNBOOK, ARCHITECTURE, SECURITY in repo | docs/ | Git |
| CC3.1, CC3.2 | Risk identification and analysis | Risk register | docs/SECURITY.md | Review log |
| CC3.4 | Change in risk | SECURITY.md review on architecture change | docs/SECURITY.md | Review log entries |
| CC4.1 | Monitoring of controls | `Test-ProxmoxMcpBroker.ps1 -Baseline` hourly; immutability test quarterly; access review quarterly | deploy/windows | Stored outputs |
| CC5.2 | Technology general controls | Hardening baseline, firewall rules, least-privilege services | `Set-BrokerHostBaseline.ps1`, `Set-BrokerFirewall.ps1`, installers | Test output |
| CC6.1 | Logical access security, encryption of credentials | Access + Entra MFA; enrollment; DPAPI; BitLocker; no secrets in argv | provision.sh, Protect-BrokerCredential.ps1 | Access policy JSON; credential ACL test row |
| CC6.2 | Registration and authorization of users | Ticketed enrollment in three places (Access policy, enrollment, Proxmox user) | RUNBOOK section 2 | Ticket + access review crosscheck |
| CC6.3 | Role-based access, least privilege, removal | Modes ro/operator/rw; Proxmox roles; revoke procedure; quarterly review | `setup-proxmox-access.sh`, `Set-BrokerEnrollment.ps1`, `Export-AccessReview.ps1` | `crosscheck.csv` with no unresolved findings |
| CC6.6 | Boundary protection | No inbound port; tunnel outbound only; program-scoped firewall; Access in front of every hostname; `workers_dev` and preview URLs off | `Set-BrokerFirewall.ps1`, worker/wrangler.jsonc, provision.sh | `Get-NetFirewallRule -Group ProxmoxMCP`; `provision.sh STEPS=verify` |
| CC6.7 | Transmission and movement of data | TLS end to end; TLS pin to Proxmox | broker.env, tunnel | As 164.312(e) |
| CC6.8 | Prevent unauthorized software | Hash + signature checks on every artifact; WDAC/AppLocker; Defender | installers, RUNBOOK section 9 | Install transcript; `Get-AppLockerPolicy -Effective` |
| CC7.1 | Detection of configuration changes and vulnerabilities | Baseline test; monthly patching; pip-audit and npm audit in CI | CI, RUNBOOK | CI logs; `Get-HotFix` |
| CC7.2 | Monitoring for anomalies | Alerts in RUNBOOK 8.2; uptime check expecting 401 | RUNBOOK section 8 | Alert rule export; uptime history |
| CC7.3, CC7.4 | Evaluate and respond to incidents | Emergency off; token revoke-all; key rotation | RUNBOOK sections 3 to 5 | Incident tickets; drill record |
| CC7.5 | Recovery from incidents | Rebuild from repo and artifacts | RUNBOOK sections 1 and 6 | Restore drill record |
| CC8.1 | Change management | Approved commit, CI (lint, tests, pip-audit, npm audit, secret scan), pinned artifacts, `-WhatIf` / `DRY_RUN=1` first, rollback steps | RUNBOOK sections 1 and 6 | Ticket with dry-run output; CI run link |
| CC9.1 | Business disruption risk | Fallback broker mode (access) if Workers VPC beta fails; RTO/RPO | ARCHITECTURE section 6, section 6 below | Document |
| CC9.2 | Vendor risk | BAA gates; vendor reviews of Cloudflare and Anthropic | Section 1 | Vendor file |
| A1.1 | Capacity | Rate limits; request timeout; concurrency limit | broker.env, Worker | Config |
| A1.2 | Backup and recovery infrastructure | Config backup (section 6); audit in WORM storage | Send-AuditLog.ps1 | Backup job record |
| A1.3 | Recovery testing | Yearly restore drill | Section 6 | Drill record |
| C1.1 | Identify and protect confidential information | PHI minimization (section 2); pool scoping; redaction | policy.py, output.py | Policy tests in CI |
| C1.2 | Dispose of confidential information | Local audit deleted after 400 days only when confirmed in WORM; tokens deleted on revoke; R2/Azure retention ends after 2190 days | Send-AuditLog.ps1, RUNBOOK section 4 | Event 4004 entries |

## 5. Quarterly access review procedure

1. Run on the broker:
   ```
   .\Export-AccessReview.ps1 -AccountId <account id> -WorkerHostname <worker-hostname>
   ```
   (Add `-BrokerHostname <broker-hostname>` in access mode.) The Cloudflare token needs only
   "Access: Apps and Policies Read". The Proxmox read uses the `pve-review-token` credential
   (`setup-proxmox-access.sh review-token`), which has Sys.Audit on `/access` and Pool.Audit only.
2. The system owner reviews `crosscheck.csv`. Every row must have an approved business need. Every
   finding must be resolved or accepted in the ticket.
3. Record the folder path and the printed SHA-256 of `SHA256SUMS.txt` in the review ticket.
4. Remove or change access with RUNBOOK sections 2 and 4. Run the export again and attach it.

## 6. Contingency (164.308(a)(7), A1.2, A1.3)

| Item | Value |
|---|---|
| RTO | 8 hours (rebuild the broker from repo, artifacts and re-issued tokens) |
| RPO for audit | 5 minutes (shipping interval) |
| RPO for configuration | Last config backup (daily) |
| Backed up (daily, encrypted, to the entity backup system) | `C:\ProgramData\ProxmoxMCP\config\*`, `credentials\enrollment.json`, `credentials\worker-identity.pub` |
| Not backed up (re-issue instead) | `*.dpapi` tokens, `dpapi-entropy.bin`, cloudflared `tunnel-token`. DPAPI blobs do not decrypt on another host anyway. |
| Rebuild steps | RUNBOOK section 1.3 to 1.6, then section 2 for each user (new tokens) |
| Drill | Yearly, on a test host; record time to first successful read |

## 7. Evidence calendar

| Frequency | Activity | Output kept 6 years |
|---|---|---|
| Every 5 min | Audit shipping | Blobs in the WORM container |
| Hourly | `Test-ProxmoxMcpBroker.ps1` (scheduled) | Event log and SIEM |
| Monthly | Activity review (denies, auth failures, alerts) | Review ticket |
| Monthly | Patching (Windows, cloudflared, Python packages) | Change tickets |
| Quarterly | Access review (section 5) | Evidence folder hash in ticket |
| Quarterly | `Send-AuditLog.ps1 -TestImmutability -AdminCheck` | `immutability-test-*.json` |
| Quarterly | `Test-ShippedAudit.ps1` on a sample month | Output in ticket |
| Yearly | Risk analysis review, incident drill, restore drill, this matrix review | Review logs |
