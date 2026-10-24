# Security: threat model and risk register

This document is the threat model for the Proxmox MCP build (V2). It is also the risk register
for HIPAA 164.308(a)(1)(ii)(A) and SOC 2 CC3.2. Review it when the design changes and at least
once a year. Record the review in the change log at the end.

Scale: Likelihood (L) and Impact (I) are 1 (low) to 3 (high). Risk = L x I before controls.
Residual is the rating after the controls.

## 1. Assets

| Asset | Where | Why it matters |
|---|---|---|
| Proxmox API tokens (one per person) | Broker, DPAPI files | Act on the hypervisor as that person |
| Worker identity signing key (Ed25519 private) | Worker secret | Forge any user's identity toward the broker |
| Access service token secret (access mode) | Worker secret | Pass the broker Access app |
| Tunnel token | Broker, file ACL'd to the cloudflared service | Run a connector for the tunnel and receive broker traffic |
| Enrollment list | Broker | Decides who may do what |
| Audit logs | Broker, Azure Blob, R2, Workers Logs | Evidence; contain emails and tool names, no argument values |
| Guest data on Proxmox (may include PHI) | Proxmox | The reason for the minimum-necessary controls |

## 2. Risk register

| ID | Threat | L | I | Controls | Residual |
|---|---|---|---|---|---|
| T1 | Stolen Access session or OAuth token (malware on a user device, token in a log) | 2 | 3 | Access token 10 min, session and OAuth grant 8 h, Entra Conditional Access MFA, named-user policy, per-user mode (default ro), per-user rate limit, audit with email on every line. Revoke: remove from Access policy and enrollment, revoke sessions. | Medium: a valid token works for up to 10 min after revocation; the session up to 8 h unless revoked in Access. |
| T2 | Prompt injection through VM names, notes, descriptions, tags, task logs | 3 | 2 | Every result carries an untrusted-data label. Default read-only. Destructive tools are admin tier and off by default. Human-only actions are forbidden for everyone. Claude asks the user to approve `execute_tool`. | Medium: an operator or rw user can still be tricked into approving a power or snapshot action. Keep most users ro. |
| T3 | Compromised broker host | 1 | 3 | Virtual accounts (no LocalSystem), privileges reduced to SeChangeNotifyPrivilege, no inbound port, program-scoped firewall, Defender, LSA protection, Credential Guard, BitLocker, WDAC/AppLocker, LAPS, SACL and audit policy. The broker holds only the Worker public key, so it cannot forge identities toward other systems. | High impact remains: an admin on the broker can read every Proxmox token. Tokens are pool-scoped, expire in 90 days and can be revoked on Proxmox in one command. |
| T4 | Compromised Cloudflare account or admin | 1 | 3 | Cloudflare holds no Proxmox credential. Admin MFA, least-privilege API tokens for provisioning, Cloudflare audit logs reviewed quarterly. Broker enforces mode and tier from its own enrollment. | High: an attacker with the Worker secrets can act as any enrolled user within that user's mode and Proxmox role. Response: rotate the identity key, stop the tunnel. |
| T5 | Compromised Worker secret (IDENTITY_SIGNING_KEY or service token) | 1 | 3 | Secrets only in Worker secrets; generated in a pipe, never printed. Assertions live 60 s, are bound to the body, method and path, and carry a jti that the broker caches for replay. Rotation by `provision.sh` (`ROTATE_IDENTITY_KEY=1`). | Medium: until rotation, forged assertions work for enrolled emails only and within their Proxmox roles. |
| T6 | Malicious MCP client (rogue DCR registration, phishing consent) | 2 | 2 | DCR redirect URIs limited to the two Claude callbacks plus localhost and loopback (Desktop and Code). PKCE. Access policy still requires a named user with Entra login. | Low to medium: a local malicious app on a user machine can register with a loopback redirect. It still needs the user to sign in. Disable `allow_any_on_localhost`/`loopback` if Desktop and Code are out of scope. |
| T7 | Replay of identity assertions | 2 | 2 | 60 s lifetime, jti replay cache (120 s), body hash binding, method and path binding, audience `proxmox-broker`. | Low. A restart clears the replay cache; assertions older than 60 s fail anyway. |
| T8 | SSRF through tool arguments | 2 | 3 | The broker calls only `PROXMOX_HOST:8006`. Outbound method and path allowlist, path segment validation. Windows Firewall allows the broker interpreter to reach only the Proxmox address on 8006 (and Cloudflare 443 in access mode for the JWKS). Workers VPC routes only to the configured service. Tools that download from URLs (for example ISO download) are forbidden. | Low. |
| T9 | Path traversal or API injection in path parameters | 2 | 3 | `outbound.safe_segment` rejects `..`, `/`, `?`, `#`, `%` and control characters; the final path is re-checked against the allowlist. | Low. |
| T10 | Theft of a Proxmox token | 1 | 3 | DPAPI LocalMachine with entropy plus a service-only ACL; never in argv, environment, logs or audit; privilege separation (token cannot exceed the user); pool-scoped ACLs; 90-day expiry (user expires with it); Windows Error Reporting and crash dumps off; one person per token, so the Proxmox task log names the person. | Medium: an admin on the broker or a memory dump of the broker process can extract tokens. |
| T11 | Theft of the tunnel token | 1 | 2 | File ACL'd to the cloudflared service SID; not in ImagePath, argv or environment (checked by the test script). In access mode the tunnel ingress requires the broker Access JWT, so a rogue connector receives only Worker-signed traffic. | Medium: a rogue connector can take a share of the traffic until the token is rotated. Rotate on suspicion. |
| T12 | DNS rebinding and Host header abuse against the loopback port | 1 | 2 | Host header allowlist (`broker.internal` or the broker hostname), JSON-only, no CORS, signed assertion required for every non-health request. | Low. |
| T13 | LocalSystem misuse on Windows | 2 | 3 | Neither service runs as LocalSystem. The stock `cloudflared service install` (LocalSystem, and token in ImagePath before 2026.7.3) is not used. Only the audit shipping task runs as SYSTEM: its script lives in Program Files (Administrators write only). | Low. |
| T14 | Credential theft through memory or DPAPI on Windows | 1 | 3 | Credential Guard, LSA protection (RunAsPPL), no interactive logons to the broker for daily work, Defender with tamper protection, LAPS for the local Administrator. DPAPI LocalMachine plus entropy keeps copies of the credential directory useless off the host. | Medium: any local admin can call DPAPI and read the entropy file. Treat local admin on the broker as full access to Proxmox within the MCP roles. |
| T15 | Audit tampering or deletion | 1 | 3 | Hash chain (`ph`), service cannot delete or rename the log, SACL on the log directory, shipping every 5 min to Azure Blob with a locked 2190-day immutability policy and a create-only SAS; R2 bucket lock for Worker audit; `Test-ShippedAudit.ps1`. | Low for data older than 5 min. R2 bucket lock can be removed by a Cloudflare admin (not compliance-mode WORM): Azure Blob is the system of record. |
| T16 | Insider abuse by an enrolled user | 2 | 2 | Least privilege by mode, pool-scoped Proxmox roles, forbidden human-only actions, audit with email, quarterly access review with evidence export. | Medium. |
| T17 | Supply chain (Python, WinSW, cloudflared, Python and npm packages) | 1 | 3 | Python installer and cloudflared MSI checked by SHA-256 and Authenticode signer. WinSW pinned by SHA-256. Python dependencies installed with `--require-hashes` and wheels only. No curl-pipe-shell. CI runs pip-audit and npm audit. | Medium: a pinned artifact can still contain an unknown flaw. Patch monthly. |
| T18 | PHI disclosure to Cloudflare or Anthropic | 2 | 3 | Go-live gate: BAA with Cloudflare (Enterprise) and Anthropic. Guest-content tools forbidden (agent exec, file read or write, console, cloud-init). PHI patterns redacted in output and refused in writes. Audit carries argument hashes, not values. | Medium: free-text fields can hold PHI that no pattern detects. Keep PHI out of VM names and notes by policy. |
| T19 | Workers Logs and Logpush carry user emails and tool names | 3 | 1 | Covered by the Cloudflare BAA gate. No argument values in Worker logs. | Low. |
| T20 | Other Cloudflare account members bind a Worker to the VPC Service | 1 | 2 | The broker requires a valid identity assertion signed by the Worker key. Limit the Connectivity Directory roles. | Low. |
| T21 | Denial of service (rate abuse, broker overload) | 2 | 1 | Rate limits in the Worker and on the broker, body caps, request timeout, Cloudflare edge. | Low. |
| T22 | Workers VPC beta changes or outage | 2 | 1 | The access-mode fallback is fully scripted (`BROKER_MODE=access`). | Low. |
| T23 | Unpatched Python runtime on the broker | 2 | 3 | The installer pins the Python installer by hash and signer and refuses any major.minor other than the lock's. Closed 2026-10-24: the lock (`requirements/broker-win.txt`) targets CPython 3.14, the newest line with Windows security builds (3.12 gets source-only fixes after 3.12.10). The full test suite passes on 3.14 and the hashed lock installs with `--require-hashes`. Re-check the CPython support status at each quarterly review. | Low with monthly patching. |
| T24 | Secret captured by PowerShell logging or history (module logging 4103, transcription, PSReadLine) | 2 | 3 | Secrets come only from a hidden prompt or redirected stdin; never a parameter, environment variable, temp file or cmdlet parameter (only .NET calls see them); scripts reset `$PSDefaultParameterValues`; operators run with `-NoProfile`; clipboard history off. | Low. A key logger on an admin session defeats it (T3). |
| T25 | Planted file or junction in `C:\ProgramData\ProxmoxMCP` (any user can create folders in ProgramData) | 2 | 3 | Installer locks the parent before it creates children, refuses a pre-existing folder not owned by Administrators/SYSTEM, refuses junctions and symlinks anywhere in the tree, resets owners and inheritance of log/config folders, and checks owners in the credential folder. | Low. |
| T26 | Artifact swapped between hash check and execution (TOCTOU) | 1 | 3 | Every artifact is copied into an Administrators-only staging folder; the hash and signer of that copy are checked; that copy runs. The installed `python.exe` and `cloudflared.exe` signatures are checked on every run and by the test script. | Low. |
| T27 | Spoofed Azure Arc identity endpoint (a local user listens on port 40342) makes the SYSTEM shipping task read a file | 1 | 3 | `Send-AuditLog.ps1` uses Arc only when the `himds` service runs, accepts only a small `.key` challenge file in the agent's Tokens folder, and never sends anything else. SAS mode does not use the endpoint. | Low. |
| T28 | Audit key held by one person, or lost | 2 | 2 | Two-person XOR escrow with custodians who are not the broker administrator; yearly join check; re-key on custodian change (COMPLIANCE section 7). | Low. |
| T29 | Least privilege drifts after setup (an admin adds an ACL by hand) | 2 | 2 | Daily `proxmox-mcp-selfcheck --live` measures every token's effective privileges against its mode and fails on excess; the Proxmox script converges ACLs and logs who ran it. | Low. |
| T30 | Tunnel ingress pointed at a LAN service by a compromised Cloudflare account | 1 | 3 | Firewall blocks cloudflared from private, link-local, CGNAT and multicast ranges; it can only reach the broker on loopback. | Low. |
| T31 | Third-party dependency `pywin32` (pulled in by the `mcp` SDK on Windows) contrary to the design | 2 | 1 | Installed from the hashed, wheel-only lock; not imported by the broker code. | Low; remove when the SDK drops it or the lock excludes it. |

## 3. Assumptions

- Entra Conditional Access requires MFA for the users in the Access policy.
- The broker is a dedicated server. No other workload runs on it.
- Cloudflare and Anthropic BAAs are in place before PHI can transit (see docs/COMPLIANCE.md).
- Proxmox guests that the AI may see are in one resource pool. Other guests stay outside it.

## 4. Things that are not controls

- The Worker's tool filter is a user-experience filter and a first gate. The broker decides.
- Claude's approval prompt for `execute_tool` helps, but users can set it to always allow.
- DPAPI LocalMachine does not protect against a local administrator.
- The installer's checks do not stop an administrator who wants to weaken the host. Separation
  of duties (COMPLIANCE 6.9, 6.10) and the SACL and Security log do.

## 5. Review log

| Date | Change | Reviewer |
|---|---|---|
| 2026-10-24 | First version for V2 (Worker + Windows broker) | DEPLOY agent (draft, needs owner review) |
| 2026-10-24 | H10 hardening review: T23 to T31 added; TOCTOU, ACL, logging and escrow controls | H10 agent (draft, needs SO review) |
