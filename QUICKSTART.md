# Quick start

There is no quick start for production. The broker holds Proxmox credentials for
each person, so a correct installation needs the steps in
[docs/RUNBOOK.md](docs/RUNBOOK.md).

To try the code on a workstation against a lab cluster, follow
[README.md: Local development](README.md#local-development). Use a lab API token
with few privileges and keep `MCP_LOCAL_MODE=ro`.

To run the tests:

```sh
uv venv -q .venv -p 3.12
uv pip install -q -p .venv -e . pytest pytest-asyncio pytest-cov ruff
.venv/bin/pytest -q --no-cov
```
