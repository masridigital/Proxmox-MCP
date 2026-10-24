# Setup

Every deployment is driven by one file and one command:

```sh
cp deploy/provision.example.toml deploy/provision.toml   # fill it; git-ignored; no secrets
python3 deploy/plan.py deploy/provision.toml             # validated, ordered steps
```

| Read | When |
|---|---|
| [README.md: Setup](README.md#setup) | Prerequisites and the eight phases |
| [AGENTS.md](AGENTS.md) | You are an AI agent, or you direct one |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | Detail for each step, day-2 tasks, emergency off |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The design and the trust boundaries |
| [docs/SECURITY.md](docs/SECURITY.md), [docs/COMPLIANCE.md](docs/COMPLIANCE.md) | Risks, controls, audit evidence |

Rules that apply to every installation:

1. Give each person a separate Proxmox user and a separate API token with privilege
   separation on. Never share a token. Never enroll `root@pam`.
2. Give each token only the Proxmox roles it needs, on a pool or path, not on `/`.
3. Keep tokens in the broker credentials directory. Never put a token in a file of this
   repository, in `.env`, in the registry, on a command line or in a chat.
4. Verify the Proxmox certificate: a SHA-256 pin or a CA bundle.
5. Keep the broker on `127.0.0.1`. Open no inbound port.
6. Sign the BAAs with Cloudflare and Anthropic before any system with PHI is in scope.
