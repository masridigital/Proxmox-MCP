# Setup

The upstream setup guide described a local stdio server with one shared Proxmox
account, a password option and SSL verification off. That setup is not safe for
this fork, and it is removed.

Use these documents:

| Task | Document |
|---|---|
| Install the broker on Windows Server 2025 | [docs/RUNBOOK.md](docs/RUNBOOK.md) |
| Create the Cloudflare Tunnel, Access applications, Worker and MCP portal | [docs/RUNBOOK.md](docs/RUNBOOK.md) |
| Create one Proxmox user and one privilege-separated API token per person | [docs/RUNBOOK.md](docs/RUNBOOK.md) |
| Enroll a person (email, mode, token file) | [README.md](README.md#configuration), [docs/RUNBOOK.md](docs/RUNBOOK.md) |
| Understand the design | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Review the risks and controls | [docs/SECURITY.md](docs/SECURITY.md), [docs/COMPLIANCE.md](docs/COMPLIANCE.md) |
| Run the server on a workstation for development | [README.md](README.md#local-development) |

Rules that apply to every installation:

1. Give each person a separate Proxmox user and a separate API token with
   privilege separation on. Never share a token. Never enroll `root@pam`.
2. Give each token only the Proxmox roles it needs, on a pool or path, not on `/`.
3. Keep tokens in the credentials directory. Never put a token in `.env`, in the
   registry, on a command line or in a chat.
4. Verify the Proxmox certificate: set `PROXMOX_CA_BUNDLE` or
   `PROXMOX_TLS_FINGERPRINT`.
5. Keep the broker on `127.0.0.1`. Open no inbound port.
6. Sign the BAAs with Cloudflare and Anthropic before any system with PHI is in
   scope.
