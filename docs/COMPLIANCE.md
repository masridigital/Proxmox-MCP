# Compliance: HIPAA Security Rule and SOC 2 control matrix

This document maps the HIPAA Security Rule (45 CFR 164.308, 164.310, 164.312, 164.314,
164.316) and the SOC 2 Trust Services Criteria (2017, points of focus revised 2022: CC1 to
CC9, A1, C1) to the controls of this build. Each row names the control, the type, the file or
configuration that implements it, the owner, the frequency and the evidence that an auditor
collects.

Scope: the Proxmox MCP data path (Claude, Cloudflare Access and Worker, Windows broker,
Proxmox VE API) and the people who operate it.

Commands run on the broker in an elevated Windows PowerShell 5.1 or PowerShell 7 with
`-NoProfile`, unless the row says otherwise. `<...>` values are placeholders. This repository
never holds real host names, addresses, account ids, AUD tags, e-mail addresses or VM names.

## 0. How to read this document

Control types:

| Type | Meaning |
|---|---|
| T | Technical control. The code or the deploy scripts enforce it. |
| O | Organizational control. The code cannot provide it. The entity must operate it. Section 6 gives a template or checklist for each. |
| T+O | The code enforces part; people operate the rest. |
| I | Inherited from a vendor (Cloudflare, Anthropic, Microsoft). Evidence is the vendor report plus the BAA. |

Owners (roles, not names; the entity records the named person per role in the role register,
section 6.10):

| Code | Role |
|---|---|
| SO | Security Officer (HIPAA 164.308(a)(2) designated official) |
| PO | Privacy Officer |
| SYS | System Owner of the Proxmox MCP service |
| BA | Broker Administrator (Windows) |
| PA | Proxmox Administrator |
| CFA | Cloudflare Administrator |
| KCA, KCB | Key Custodian A and Key Custodian B (two different people; neither is BA) |
| HR | Human Resources |
| IA | Internal Auditor (independent of SYS and BA) |

Frequencies: C continuous, 5m every 5 minutes, H hourly, D daily, M monthly, Q quarterly,
Y yearly, E on event (hire, change, incident, termination).

## 1. Go-live gates (all must be true before PHI can transit)

| Gate | Requirement | Owner | Evidence |
|---|---|---|---|
| G1 | Signed BAA with Cloudflare. The Cloudflare BAA needs the Enterprise plan. It must cover Access, Workers, Workers Logs and Logpush, R2, Tunnel and Workers VPC. | SO | BAA copy and plan confirmation in the vendor file |
| G2 | Signed BAA with Anthropic for the Claude plan in use. | SO | BAA copy in the vendor file |
| G3 | Risk analysis done and accepted (docs/SECURITY.md, section 6.4 template). | SO, SYS | Signed risk acceptance |
| G4 | `Test-ProxmoxMcpBroker.ps1 -Baseline -Live` shows no FAIL; `provision.sh STEPS=verify` passes. | BA, CFA | Saved outputs |
| G5 | WORM test passes. | BA | `ship\immutability-test-*.json` with `pass: true` |
| G6 | First access review done. | SYS | `evidence\access-review-<date>\SHA256SUMS.txt` hash in the ticket |
| G7 | Audit HMAC key escrowed by two custodians (section 7). | KCA, KCB | `evidence\key-escrow\escrow-<kid>-*.json`, signed escrow log |
| G8 | Workforce training done for every enrolled user and every administrator (6.1). | HR, SO | Training records |
| G9 | Incident response plan and contingency plan approved (6.5, 6.6). | SO | Signed plans |
| G10 | The Python runtime decision is closed: the lock targets a CPython line with current Windows security builds (docs/SECURITY.md T23). | SYS | Met 2026-10-24: lock targets CPython 3.14 (commit history of requirements/broker-win.txt) |

Until G1 and G2 are true, the build may run only against Proxmox guests that hold no PHI, and
nobody may put PHI in guest names, notes, descriptions or tags.

## 2. PHI minimization (164.502(b) minimum necessary)

The build keeps PHI out of the data path by design. It does not depend on the redaction filter.

| Measure | Implementation |
|---|---|
| Guest content is never read | Tools for guest agent exec, file read and write, consoles and shells are in the forbidden tier (`proxmox_mcp/policy.py`). Proxmox roles exclude `VM.GuestAgent.Unrestricted`, `VM.GuestAgent.File*`, `VM.Console` and `VM.Config.Cloudinit` (`deploy/proxmox/setup-proxmox-access.sh`). `VM.GuestAgent.Audit` (OS name, file system list, NIC addresses) is the only guest-agent privilege. |
| Only one pool is visible | ACLs on `/pool/<pool>` only; the script refuses `/` |
| Read-only by default | Mode `ro` is the default; admin tier needs `rw` and `MCP_ALLOW_ADMIN_TOOLS=1` |
| PHI patterns redacted in output, refused in writes | `proxmox_mcp/output.py`, `proxmox_mcp/phi.py` (broker); the Worker repeats the redaction |
| Audit holds no values | Argument keys and SHA-256 of canonical arguments only |
| Host logs | `Sys.Syslog` is off unless `NODE_SYSLOG=1` |
| Policy | Guest names, notes, descriptions and tags must not contain PHI (acceptable use statement, 6.1) |

## 3. HIPAA Security Rule matrix

R = required implementation specification, A = addressable. For each addressable item the
decision is "implemented" unless the row says otherwise.

### 3.1 164.308 Administrative safeguards

| Citation | Requirement | Type | Control | Implemented in | Owner | Freq | Evidence |
|---|---|---|---|---|---|---|---|
| (a)(1)(ii)(A) R | Risk analysis | T+O | Threat model and risk register (likelihood, impact, controls, residual) | docs/SECURITY.md; template 6.4 | SO | Y, E | Signed review log in SECURITY.md section 5 |
| (a)(1)(ii)(B) R | Risk management | T+O | This matrix; residual risks accepted by SO; risk treatment tickets | SECURITY.md, this file | SO | Q | Risk treatment tickets, signed acceptance |
| (a)(1)(ii)(C) R | Sanction policy | O | Sanctions for misuse of the MCP or PHI | Template 6.2 | HR, SO | E | Signed policy; sanction records |
| (a)(1)(ii)(D) R | Information system activity review | T+O | Monthly review of broker audit denies, auth failures, Access logs, selfcheck events, alert history | RUNBOOK 8; checklist 6.9 | SO | M | Review ticket with query output |
| (a)(2) R | Assigned security responsibility | O | SO named in the role register | 6.10 | SYS | Y, E | Role register |
| (a)(3)(ii)(A) A | Authorization and supervision | T+O | Access only by approved request; mode decided by SYS | Access request form 6.3; `Set-BrokerEnrollment.ps1` | SYS | E | Approved request ticket |
| (a)(3)(ii)(B) A | Workforce clearance | O | HR clearance before enrollment | 6.3 | HR | E | HR record referenced in the request |
| (a)(3)(ii)(C) A | Termination procedures | T+O | Revoke in Access, enrollment and Proxmox the same day; checklist | RUNBOOK 4; 6.3 | SYS, PA | E | Termination checklist with timestamps; next access review shows no entry |
| (a)(4)(ii)(A) R | Isolate clearinghouse functions | n/a | Not a clearinghouse | | SO | Y | Statement in the risk analysis |
| (a)(4)(ii)(B) A | Access authorization | T | Named-user Access policy; enrollment modes; pool-scoped Proxmox roles; one person one key (enforced by the broker and by `Set-BrokerEnrollment.ps1`) | `provision.sh`, `enrollment.json`, `setup-proxmox-access.sh` | SYS | E | `Export-AccessReview.ps1` folder |
| (a)(4)(ii)(C) A | Access establishment and modification | T+O | Enrollment and mode changes only by ticket; ACLs converge on every run; every run of the Proxmox script logs who ran it (syslog tag `proxmox-mcp-access`) | `Set-BrokerEnrollment.ps1`, `setup-proxmox-access.sh` | SYS, PA | E, Q | Ticket; syslog lines; access review crosscheck |
| (a)(5)(ii)(A) A | Security reminders | O | Quarterly reminder to users (PHI in VM names, phishing of OAuth consent) | 6.1 | SO | Q | Sent reminder |
| (a)(5)(ii)(B) A | Protection from malicious software | T | Defender real-time, behaviour, script scanning, network protection, tamper protection; signed and hash-pinned binaries; WDAC/AppLocker | `Set-BrokerHostBaseline.ps1`, installers | BA | C, D | `Test-ProxmoxMcpBroker.ps1 -Baseline` (Defender, binary integrity rows) |
| (a)(5)(ii)(C) A | Log-in monitoring | T | Access login logs; broker auth-failure alert; Windows logon audit | RUNBOOK 8.2; baseline audit policy | SO | C, M | Alert rule export; monthly review |
| (a)(5)(ii)(D) A | Password management | T | No passwords in the path: Entra SSO with MFA; Proxmox users have no password; tokens expire (max 365 days, default 90); LAPS for local Administrator | `setup-proxmox-access.sh`, baseline | PA, BA | C | `pveum user list` (no password), selfcheck `token_expiry` rows |
| (a)(6)(i) R | Security incident procedures | O | Incident response plan | Template 6.5 | SO | Y | Approved plan |
| (a)(6)(ii) R | Response and reporting | T+O | Emergency off (Access, `STEPS=off`, tunnel stop, `revoke-all`); evidence preservation; breach assessment (164.402) | RUNBOOK 5; 6.5 | SO | E, Y | Incident records; yearly drill record |
| (a)(7)(ii)(A) R | Data backup plan | T+O | Config backup (not tokens); audit in WORM storage | Section 5 | BA | D | Backup job record |
| (a)(7)(ii)(B) R | Disaster recovery plan | T+O | Rebuild from repo, release artifacts and re-issued tokens; RTO 8 h | Section 5; RUNBOOK 1 | SYS | Y | Restore drill record |
| (a)(7)(ii)(C) R | Emergency mode operation plan | O | During an outage, Proxmox admins work in the Proxmox GUI directly; the MCP is a convenience path, not a dependency for patient care | 6.6 | SYS | Y | Approved plan |
| (a)(7)(ii)(D) A | Testing and revision | O | Yearly restore drill and incident drill | 6.6 | SYS, SO | Y | Drill records |
| (a)(7)(ii)(E) A | Applications and data criticality | O | Criticality: MCP access "low" (no PHI system depends on it); audit data "high" | 6.6 | SYS | Y | Criticality table in the plan |
| (a)(8) R | Evaluation | O | Yearly technical and non-technical evaluation of this matrix; after each architecture change | 6.4 | SO, IA | Y, E | Evaluation report |
| (b)(1), (b)(3) R | Business associate contracts | O | BAAs with Cloudflare and Anthropic (G1, G2); vendor reviews | 6.7, 6.8 | SO | Y | BAA copies; vendor review records |

### 3.2 164.310 Physical safeguards

| Citation | Requirement | Type | Control | Implemented in | Owner | Freq | Evidence |
|---|---|---|---|---|---|---|---|
| (a)(1) | Facility access controls | O/I | Broker in a controlled site or data center | Entity facility policy | SO | Y | Facility policy, visitor logs |
| (a)(2)(i) A | Contingency operations | O | Site access during an emergency per the contingency plan | 6.6 | SO | Y | Plan |
| (a)(2)(ii) A | Facility security plan | O/I | Entity plan covers the broker room | Entity | SO | Y | Plan |
| (a)(2)(iii) A | Access control and validation | O/I | Badge access to the room | Entity | SO | Q | Badge reports |
| (a)(2)(iv) A | Maintenance records | O/I | Repairs to the room and the server recorded | Entity | SO | E | Maintenance log |
| (b) R | Workstation use | O | Admin work only from a privileged access workstation; no browsing on the broker | RUNBOOK 9; 6.1 | SO | Y | Policy; inventory |
| (c) R | Workstation security | T+O | Broker: no interactive daily logons, RDP off or NLA from the management network only; console locked | Baseline, RUNBOOK 9 | BA | Q | Test output (RDP row) |
| (d)(1) R | Device and media controls | T | BitLocker with TPM on every broker volume; DPAPI blobs do not decrypt off the host | `Set-BrokerHostBaseline.ps1` | BA | C | Test output (BitLocker rows) |
| (d)(2)(i) R | Disposal | O | Wipe or destroy broker disks (NIST SP 800-88) and escrow-share media at end of life | 6.6 | BA, SO | E | Certificate of destruction |
| (d)(2)(ii) R | Media re-use | O | Same as disposal before re-use | 6.6 | BA | E | Wipe record |
| (d)(2)(iii) A | Accountability | O | Asset register entry for the broker and the two escrow media | 6.10 | SO | Q | Asset register |
| (d)(2)(iv) A | Data backup and storage | T | Config backup before moving equipment; audit already in WORM | Section 5 | BA | E | Backup record |

### 3.3 164.312 Technical safeguards

| Citation | Requirement | Type | Control | Implemented in | Owner | Freq | Evidence |
|---|---|---|---|---|---|---|---|
| (a)(1) | Access control | T | Access policy, enrollment, tool tiers, outbound allowlist, Proxmox roles | Worker, `policy.py`, `outbound.py`, `setup-proxmox-access.sh` | SYS | C | Access review folder; `selfcheck --live` |
| (a)(2)(i) R | Unique user identification | T | One Access identity, one Proxmox user and one token per person (shared user or token refused by the broker); email on every audit line | `enrollment.py`, audit | SYS | C | Sample audit lines; Proxmox task log shows `mcp-<short>@pve` |
| (a)(2)(ii) R | Emergency access procedure | O | Proxmox admins keep direct GUI access outside the MCP; break-glass accounts per the entity | RUNBOOK 5; 6.6 | PA | Y | Procedure; drill record |
| (a)(2)(iii) A | Automatic logoff | T | Access token max 10 min; session and OAuth grant max 8 h (provision.sh refuses longer); identity assertion 60 s | `provision.sh` | CFA | C | `cloudflare-access.json` in the access review; verify output |
| (a)(2)(iv) A | Encryption and decryption | T | BitLocker (TPM); DPAPI LocalMachine + entropy for secrets; Worker secrets encrypted by Cloudflare | Baseline, `Protect-BrokerCredential.ps1` | BA | C | Test output; `credentials` holds only `*.dpapi` secrets |
| (b) R | Audit controls | T | Broker keyed hash-chained JSONL (`MCP_AUDIT_HMAC=required`); Worker AuditChain to R2; Workers Logs; Windows Security log; Cloudflare audit logs | `audit.py`, Worker, `Send-AuditLog.ps1`, baseline | SO | C, 5m | `proxmox-mcp-audit-verify` output; WORM listing |
| (c)(1) A | Integrity | T | Hash chain (`ph`, `seq`), HMAC `mac`, verify anchors in WORM, chunk SHA-256 chain, Azure locked immutability 2190 days, R2 bucket lock, SACL on logs; the service cannot delete or re-permission its logs (no D, OWNER RIGHTS) | `Send-AuditLog.ps1`, `Install-ProxmoxMcpBroker.ps1` | SO | C, Q | Immutability test JSON; `Test-ShippedAudit.ps1` output |
| (c)(2) A | Mechanism to authenticate ePHI | T | Same as (c)(1); escrowed key lets auditors verify every line | Section 7 | IA | Q | Verify run with `--require-mac --anchor` |
| (d) R | Person or entity authentication | T+O | Entra with MFA by Conditional Access; Access `require login_method` and `auth_method mfa` (`REQUIRE_MFA=1`); broker accepts only Worker-signed assertions | `provision.sh`, `identity_assertion.py`; Entra CA (O) | CFA, SO | C | Access policy JSON; Entra CA export |
| (e)(1) | Transmission security | T | TLS 1.2+ at the edge; tunnel; TLS pinned to Proxmox; plaintext only on loopback | tunnel service, `broker.env` | BA | C | Test listener row; `broker.env` |
| (e)(2)(i) A | Integrity controls | T | TLS; assertion binds body hash, method and path | `identity_assertion.py` | BA | C | Tests in CI |
| (e)(2)(ii) A | Encryption | T | As (e)(1); TLS 1.2 forced in every PowerShell download path | Common `Initialize-PmcTlsProtocol` | BA | C | Code review |

### 3.4 164.314 Organizational requirements

| Citation | Requirement | Type | Control | Owner | Freq | Evidence |
|---|---|---|---|---|---|---|
| (a)(1) R | Business associate contracts | O | BAAs with Cloudflare and Anthropic; no PHI before G1, G2 | SO | Y | BAA copies |
| (a)(2)(i) | BAA content (safeguards, subcontractors, incident reporting, termination) | O | BAA checklist 6.7 for each vendor | SO, PO | Y | Completed checklist |
| (a)(2)(iii) | Subcontractor BAAs | O | Vendor confirms flow-down to its subprocessors | SO | Y | Vendor statement |
| (b) | Group health plan requirements | n/a | The entity is not a group health plan sponsor for this system | SO | Y | Statement in the risk analysis |

### 3.5 164.316 Policies and procedures and documentation

| Citation | Requirement | Type | Control | Owner | Freq | Evidence |
|---|---|---|---|---|---|---|
| (a) R | Policies and procedures | T+O | This file, SECURITY.md, RUNBOOK.md, ARCHITECTURE.md in version control; entity policies (section 6) | SO | Y | Git history; signed policies |
| (b)(1) R | Documentation | T+O | Same, plus change and review tickets | SO | C | Git log, tickets |
| (b)(2)(i) R | Time limit: 6 years | T | Azure Blob locked retention 2190 days; R2 lock 2190 days; evidence files uploaded to WORM; documents kept 6 years in git | SO | C | `az storage container immutability-policy show`; verify output (R2 lock row) |
| (b)(2)(ii) R | Availability | T+O | Docs in the repo; evidence in WORM; auditor read role on the container | SO | Y | Access list of the container |
| (b)(2)(iii) R | Updates | O | Yearly review and after changes | SO | Y, E | Review log |

## 4. SOC 2 matrix

| Criterion | Control | Type | Implemented in | Owner | Freq | Evidence |
|---|---|---|---|---|---|---|
| CC1.1 | Integrity and ethical values: code of conduct, acceptable use for enrolled users | O | 6.1 | HR | Y | Signed acknowledgements |
| CC1.2 | Board or management oversight of security | O | Yearly security report to management | SO | Y | Report and minutes |
| CC1.3 | Structure, authority, responsibility | O | Role register 6.10 | SO | Y | Role register |
| CC1.4 | Competence: training of administrators and users | O | 6.1 | HR, SO | Y | Training records |
| CC1.5 | Accountability: sanctions | O | 6.2 | HR | E | Sanction records |
| CC2.1 | Quality information: keyed audit with correlation ids (Cf-Ray, jti); version, catalog hash and config hash in the start event | T | `audit.py`, `config.py` | SO | C | Start event sample |
| CC2.2 | Internal communication of responsibilities and procedures | T+O | RUNBOOK, ARCHITECTURE, SECURITY in repo; reminders 6.1 | SO | Q | Git; reminders |
| CC2.3 | External communication: vendors, users, incident notices | O | BAA contacts; breach notification in 6.5 | SO, PO | E | Contact list; notices |
| CC3.1 | Objectives specified | O | Risk analysis states objectives (confidentiality of PHI, integrity of audit) | SO | Y | Risk analysis |
| CC3.2 | Risk identification and analysis | T+O | Risk register | SO | Y | SECURITY.md review log |
| CC3.3 | Fraud risk | O | Insider abuse (T16), key custodian separation (section 7) | SO | Y | Risk analysis |
| CC3.4 | Change in risk | O | SECURITY.md review on each architecture change | SO | E | Review log entries |
| CC4.1 | Ongoing and separate evaluations | T+O | Hourly offline selfcheck; daily `selfcheck --live`; quarterly immutability test and access review; yearly IA review | `Invoke-BrokerSelfCheck.ps1`, `Send-AuditLog.ps1`, `Export-AccessReview.ps1` | SO, IA | H, D, Q, Y | Evidence files in WORM |
| CC4.2 | Communication of deficiencies | O | Findings tracked to closure; SIEM alerts to SO | SO | E | Tickets |
| CC5.1 | Control activities selected | T+O | This matrix | SO | Y | This file |
| CC5.2 | Technology general controls | T | Hardening baseline, firewall rules, least-privilege services, signed artifacts | Baseline, firewall, installers | BA | C | Test output |
| CC5.3 | Policies deployed | O | Section 6 policies approved and published | SO | Y | Signed policies |
| CC6.1 | Logical access, encryption of credentials | T | Access + Entra MFA; enrollment; DPAPI; BitLocker; no secrets in argv, env, temp files, logs or cmdlet parameters | provision.sh, Protect-BrokerCredential.ps1, Common | SO | C | Access policy JSON; credential ACL row |
| CC6.2 | Registration and authorization of users | T+O | Ticketed enrollment in three places (Access policy, enrollment, Proxmox user) | RUNBOOK 2; 6.3 | SYS | E | Ticket + access review crosscheck |
| CC6.3 | Role-based access, least privilege, removal | T+O | Modes ro/operator/rw; pool-scoped roles; revoke; quarterly review; **daily `proxmox-mcp-selfcheck --live` measures each token's effective privileges against its mode** (section 8) | `setup-proxmox-access.sh`, `Set-BrokerEnrollment.ps1`, `Invoke-BrokerSelfCheck.ps1` | SYS, PA | D, Q | `evidence\selfcheck\selfcheck-live-*.json` (WORM copies); `crosscheck.csv` |
| CC6.4 | Physical access | O/I | 164.310(a) rows | SO | Q | Badge reports |
| CC6.5 | Disposal of assets | O | 164.310(d)(2) rows | BA | E | Destruction certificates |
| CC6.6 | Boundary protection | T | No inbound port; tunnel outbound only; program-scoped firewall (cloudflared blocked from private ranges); Access in front of every hostname; `workers_dev` and preview URLs off (verified) | `Set-BrokerFirewall.ps1`, provision.sh | BA, CFA | C | `provision.sh STEPS=verify`; firewall rule export |
| CC6.7 | Transmission and movement of data | T | TLS end to end; TLS pin to Proxmox | broker.env, tunnel | BA | C | As 164.312(e) |
| CC6.8 | Prevent unauthorized software | T | Hash of the staged copy that runs + Authenticode signer; WDAC/AppLocker; Defender | installers, RUNBOOK 9 | BA | C | Test binary integrity row; `Get-AppLockerPolicy -Effective` |
| CC7.1 | Detect configuration changes and vulnerabilities | T+O | Baseline test; monthly patching; pip-audit and npm audit in CI; supported Python line (T23) | CI, RUNBOOK | BA | M | CI logs; `Get-HotFix` |
| CC7.2 | Monitor for anomalies | T | Alerts RUNBOOK 8.2; uptime check expecting 401; selfcheck events 4203/4204 | RUNBOOK 8 | SO | C | Alert rule export; uptime history |
| CC7.3 | Evaluate security events | O | Triage per IR plan | 6.5 | SO | E | Incident tickets |
| CC7.4 | Respond to incidents | T+O | Emergency off; token revoke-all; key rotation | RUNBOOK 3 to 5; 6.5 | SO | E, Y | Incident tickets; drill record |
| CC7.5 | Recover from incidents | T+O | Rebuild; rollback to previous venv | RUNBOOK 1, 6 | SYS | E, Y | Restore drill record |
| CC8.1 | Change management | T+O | Approved change (6.9); CI; pinned artifacts; `-WhatIf` / `DRY_RUN=1` first; staged venv switch with automatic rollback; `-Rollback` | RUNBOOK 1, 6; 6.9 | SYS | E | Ticket with dry-run output, CI link, installed.json |
| CC9.1 | Business disruption risk | T+O | Access-mode fallback if Workers VPC beta fails; RTO/RPO | ARCHITECTURE 6, section 5 | SYS | Y | Document |
| CC9.2 | Vendor and business partner risk | O | BAA gates; yearly vendor review (6.8) | SO | Y | Vendor file |
| A1.1 | Capacity | T | Rate limits; request, header and body timeouts; concurrency limit | broker.env, Worker | BA | C | Config hash in start event |
| A1.2 | Environmental protections, backup and recovery infrastructure | T+O | Config backup (section 5); audit in WORM; UPS and site per entity | Send-AuditLog.ps1; entity | BA | D | Backup job record |
| A1.3 | Recovery plan testing | O | Yearly restore drill | 6.6 | SYS | Y | Drill record |
| C1.1 | Identify and protect confidential information | T | PHI minimization (section 2); pool scoping; redaction | policy.py, output.py | PO | C | Policy tests in CI |
| C1.2 | Dispose of confidential information | T+O | Local audit deleted after 400 days only when confirmed in WORM; tokens deleted on revoke; WORM retention ends after 2190 days; media disposal 6.6 | Send-AuditLog.ps1, RUNBOOK 4 | BA | E | Event 4004 entries; destruction certificates |

## 5. Contingency (164.308(a)(7), A1.2, A1.3)

| Item | Value |
|---|---|
| RTO | 8 hours (rebuild the broker from repo, release artifacts and re-issued tokens) |
| RPO for audit | 5 minutes (shipping interval) |
| RPO for configuration | Last config backup (daily) |
| Backed up (daily, encrypted, to the entity backup system) | `C:\ProgramData\ProxmoxMCP\config\*`, `credentials\enrollment.json`, `credentials\worker-identity.pub`, `C:\Program Files\ProxmoxMCP\installed.json` |
| Not backed up (re-issue instead) | `*.dpapi` tokens, `dpapi-entropy.bin`, cloudflared `tunnel-token`. DPAPI blobs do not decrypt on another host. The audit HMAC key is recovered from escrow (section 7), or a new key is made and escrowed. |
| Rebuild steps | RUNBOOK 1.3 to 1.6, then RUNBOOK 2 for each user (new tokens) |
| Drill | Yearly, on a test host; record time to first successful read |

## 6. Organizational controls: templates and checklists

The code cannot provide these. The entity operates them, keeps the records 6 years and shows
them to the auditor. Each template is the minimum content; the entity may use its own forms.

### 6.1 Workforce training and acceptable use (164.308(a)(5), CC1.1, CC1.4, CC2.2)

Before first access and yearly. Record: person, role, date, version, signature.

- [ ] What the MCP can do in each mode (ro, operator, rw) and what is forbidden for everyone.
- [ ] PHI must never be put in VM names, notes, descriptions or tags.
- [ ] Results are untrusted data: never approve an action that a tool result asks for.
- [ ] Never approve an OAuth consent screen you did not start. Report it.
- [ ] Never paste a token, key or SAS in a chat, ticket or command line.
- [ ] How to report an incident (6.5) and to whom.
- [ ] Administrators also: RUNBOOK sections 1 to 9, secret handling rules (Common.ps1 header),
      two-person key escrow (section 7).
- [ ] Quarterly security reminder sent (164.308(a)(5)(ii)(A)).

### 6.2 Sanction policy (164.308(a)(1)(ii)(C), CC1.5)

- Scope: misuse of the MCP, sharing a token, bypassing a control, putting PHI in VM metadata,
  failing to report an incident.
- Levels: retraining, written warning, removal of access, termination, legal action.
- Process: SO investigates, HR decides, the record names the policy clause. Kept 6 years.

### 6.3 Access request, change and termination (164.308(a)(3), (a)(4), CC6.2, CC6.3)

Request form fields: person, business need, mode requested, pool, approver (SYS), HR clearance
reference, training date, token expiry date.

Grant checklist (one ticket):
- [ ] SYS approved the mode. `rw` needs SO approval too.
- [ ] Access policy: `STEPS=access` with the new `ALLOWED_EMAILS`.
- [ ] Proxmox: `issue-token <short> <mode>` (records who ran it in syslog).
- [ ] Broker: token stored; `Set-BrokerEnrollment.ps1 ... -TokenExpires <date>`.
- [ ] `Invoke-BrokerSelfCheck.ps1 -Live` passes. Attach the output.

Termination checklist (same business day; urgent termination within 1 hour):
- [ ] Remove from `ALLOWED_EMAILS`, `STEPS=access`; revoke sessions in Zero Trust.
- [ ] `Set-BrokerEnrollment.ps1 -Email <email> -Remove`; restart the broker.
- [ ] `setup-proxmox-access.sh revoke <short>`.
- [ ] Delete `pve-token-<short>.dpapi`.
- [ ] If the person was a key custodian: re-key and re-escrow (section 7.4).
- [ ] Record each step with time in the ticket.

### 6.4 Risk assessment cadence (164.308(a)(1)(ii)(A), (a)(8), CC3.1 to CC3.4)

- Yearly full review of docs/SECURITY.md, and on every architecture change, new vendor, new
  tool tier or incident.
- For each risk: likelihood, impact, controls, residual, owner, treatment, due date.
- SO signs the acceptance of every residual rated Medium or High.
- Inputs: incidents, monthly activity reviews, selfcheck failures, vendor reports, CVEs in
  pinned components.

### 6.5 Incident response plan (164.308(a)(6), CC7.3, CC7.4, CC2.3)

1. Detect: SIEM alert (RUNBOOK 8.2), user report, vendor notice.
2. Triage (SO, within 1 hour): severity, PHI involved or not.
3. Contain: RUNBOOK 5 emergency off. Keep audit files; run `Send-AuditLog.ps1` once by hand.
4. Preserve evidence: WORM blobs, Windows event logs, Access logs, Proxmox task log.
5. Eradicate: rotate the affected secrets (RUNBOOK 3); rebuild the broker if host compromise is
   suspected.
6. Recover: re-enable by approved change only.
7. Breach assessment (PO): the four-factor test of 164.402; notifications per 164.404 to
   164.410 and the BAAs (vendor duty to report to the entity).
8. Lessons learned within 14 days; update SECURITY.md.
Drill: yearly tabletop or live drill of steps 1 to 6.

### 6.6 Contingency plan, emergency mode, testing, disposal (164.308(a)(7), 164.310(d), A1.3)

- Emergency mode: the MCP is not required for patient care. Proxmox admins use the Proxmox GUI
  with their own accounts. Audit continues on the broker; shipping resumes when the network
  returns (no loss up to local disk capacity).
- Criticality: MCP access low; audit data high; escrowed key high.
- Yearly restore drill: rebuild on a test host from the release record, enroll one test user,
  run one read, verify the audit chain. Record start time, end time, issues.
- Disposal: NIST SP 800-88 purge or destroy for broker disks and escrow media; certificate kept.

### 6.7 Business associate agreement checklist (164.308(b), 164.314(a), CC9.2)

- [ ] Signed by both parties; effective date before PHI transit.
- [ ] Covers the products in use (Cloudflare: Access, Workers, Workers Logs/Logpush, R2,
      Tunnel, Workers VPC. Anthropic: the Claude plan and API in use).
- [ ] Permitted uses and disclosures; minimum necessary.
- [ ] Safeguards per the Security Rule; subcontractor flow-down.
- [ ] Breach and security incident reporting: time limit and contact.
- [ ] Return or destruction of PHI at termination.
- [ ] Access to books and records for HHS.

### 6.8 Vendor management (CC9.2)

Yearly per vendor (Cloudflare, Anthropic, Microsoft for Windows and Entra, Python Software
Foundation and PyPI as software sources, WinSW project): current SOC 2 Type II or ISO 27001
report reviewed, exceptions noted, complementary user entity controls (CUECs) mapped to this
matrix, BAA status, open incidents. WinSW has no attestation: the hash pin and WDAC rule are the
compensating controls; record that decision.

### 6.9 Change approval and activity review (CC8.1, 164.308(a)(1)(ii)(D))

Change ticket fields: description, risk, approver (SYS; SO for security-relevant changes),
release commit, CI run, artifact SHA-256 values, dry-run output (`-WhatIf`, `DRY_RUN=1`),
rollback plan (`-Rollback`, `wrangler rollback`), post-change test output. No self-approval.

Monthly activity review checklist (SO):
- [ ] Broker audit: denies by user and reason; auth failures; any `mac` or chain error.
- [ ] Selfcheck events 4202, 4203, 4204 of the month and their closure.
- [ ] Shipping events 4102, 4105, 4106.
- [ ] Access logs: denied logins, new devices, sign-ins outside expected hours.
- [ ] Proxmox syslog `proxmox-mcp-access` lines match approved tickets.
- [ ] Windows: logons to the broker, new services, SACL events on logs and credentials.

### 6.10 Role register and asset register (164.308(a)(2), 164.310(d)(2)(iii), CC1.3)

Role register: role code (section 0), named person, deputy, start date. KCA and KCB must be two
different people, and neither may be BA (separation of duties). Asset register: broker host,
its disks, escrow media A and B, with location and owner.

## 7. Audit HMAC key escrow (two-person rule)

The installer creates `audit-hmac.key` once (32 random bytes, DPAPI on the broker). Every audit
line carries an HMAC with it. Auditors need the key to verify shipped logs. No single person may
hold a usable copy.

### 7.1 Split (at first install and after every re-key)

Present: BA (operates the broker), KCA, KCB. Each custodian brings an encrypted removable medium
(for example a hardware-encrypted USB drive).

1. BA opens an elevated PowerShell on the broker. KCA and KCB watch the screen.
2. Run:
   ```
   .\Export-AuditKeyEscrow.ps1 -ShareAPath <KCA drive>:\audit-key-share-A.txt `
     -ShareBPath <KCB drive>:\audit-key-share-B.txt -CustodianA KCA -CustodianB KCB
   ```
   The script refuses the system volume, refuses both shares on one volume, never prints the
   key or a share, and never uses the clipboard. Share A is random; share B is key XOR share A.
   One share reveals nothing about the key.
3. Each custodian removes their medium, seals it in a numbered tamper-evident bag, and stores
   it in a separate safe that the other custodian cannot open.
4. All three sign the escrow log: date, key id (kid, printed by the script), bag numbers,
   safe locations. The script also writes `evidence\key-escrow\escrow-<kid>-<time>.json`
   (no key material) and event 4301; both go to WORM storage.

### 7.2 Use (audit or investigation)

1. IA requests the key in a ticket. SO approves.
2. KCA and KCB bring their bags to the auditor workstation. Check bag numbers against the log.
3. Run `Export-AuditKeyEscrow.ps1 -Join -ShareAPath ... -ShareBPath ... -OutFile .\audit-hmac.key`.
   The script checks the checksums and the kid.
4. IA runs `proxmox-mcp-audit-verify --dir <WORM copy> --key-file .\audit-hmac.key --require-mac
   --anchor <seq>:<hash>` (or `Test-ShippedAudit.ps1`), then deletes the key file.
5. Custodians reseal in new bags and update the log.

### 7.3 Yearly check

KCA and KCB open their bags in front of IA, run the join on an offline workstation, compare
the kid with the kid in current audit lines, delete the joined key, reseal. Record in the log.

### 7.4 Re-key

When a custodian leaves, a share is lost, or the key may be exposed: BA deletes
`credentials\audit-hmac.key.dpapi`, re-runs the installer (it makes a new key), restarts the
broker, and section 7.1 runs again. Keep the old shares: the verifier accepts several keys
(`--key-file` more than once) for logs written under the old key.

## 8. Least-privilege measurement: selfcheck schedule (CC6.3, 164.308(a)(4))

`Invoke-BrokerSelfCheck.ps1 -Register` creates two scheduled tasks (SYSTEM):

| Task | When | What | Evidence |
|---|---|---|---|
| `\ProxmoxMCP\SelfCheck Live` | Daily 06:10 | `proxmox-mcp-selfcheck --live`: for every enrolled token, GET `/access/permissions` over the pinned TLS; FAIL on any privilege outside the mode's allowed set, any always-forbidden privilege, or any privilege that propagates from `/`. Also token expiry, one person one key, Worker key, config. | `evidence\selfcheck\selfcheck-live-<time>.json`, uploaded once to WORM by the shipping task; event 4201 (pass), 4202 (warn), 4203 (fail), 4204 (crash) |
| `\ProxmoxMCP\SelfCheck Offline` | Hourly | Offline checks only | Event; JSON file only when not pass |

Selfcheck exit codes: 0 pass, 1 warnings, 2 failures, 3 crash. SO alerts on 4203 and 4204 and
closes each within 5 business days (critical: same day). For the auditor: the WORM listing of
`<prefix>/<host>/evidence/selfcheck/` shows one live report per day for the period; each report
shows the measured privileges per user and mode.

## 9. Evidence calendar

| Frequency | Activity | Owner | Output kept 6 years |
|---|---|---|---|
| Every 5 min | Audit shipping + verify anchor | BA (automatic) | Blobs and anchors in WORM |
| Hourly | Offline selfcheck | BA (automatic) | Events; JSON on problems |
| Daily | `selfcheck --live` (CC6.3) | BA (automatic) | `selfcheck-live-*.json` in WORM |
| Daily | Config backup | BA | Backup job record |
| Monthly | Activity review (6.9) | SO | Review ticket |
| Monthly | Patching: Windows, cloudflared, Python packages (new lock), Defender | BA | Change tickets |
| Monthly | `Test-ProxmoxMcpBroker.ps1 -Baseline -Live` | BA | Saved output |
| Quarterly | Access review (`Export-AccessReview.ps1`) | SYS | Folder hash in ticket; folder in WORM |
| Quarterly | `Send-AuditLog.ps1 -TestImmutability -AdminCheck` | BA | `immutability-test-*.json` |
| Quarterly | `Test-ShippedAudit.ps1` on a sample month with the escrowed key | IA | Output in ticket |
| Quarterly | Security reminder to users | SO | Sent reminder |
| Quarterly | Cloudflare audit log review (admin changes, API tokens) | CFA, SO | Review ticket |
| Before expiry | Rotate audit SAS (event 4106 at 30 days), service token, identity key | BA, CFA | Change tickets |
| Yearly | Risk analysis, matrix evaluation, policies, training, vendor reviews, BAA check, key escrow check, incident drill, restore drill | SO, IA, SYS | Review logs, records |
| On event | Hire, role change, termination, incident, architecture change | SYS, SO, HR | Tickets |

## 10. Organizational gaps (cannot be closed by this repository)

These remain open until the entity operates them and keeps the records:
BAAs (G1, G2); workforce training and reminders; sanction policy; role and asset registers;
risk acceptance signatures; incident response plan and drills; contingency plan, emergency mode
plan and restore drills; vendor reviews; change approval with separation of duties; monthly
activity review; physical safeguards of the broker site; media disposal; Entra Conditional
Access MFA policy; named key custodians and their safes; WDAC/AppLocker policy authoring; SIEM
alert routing.
