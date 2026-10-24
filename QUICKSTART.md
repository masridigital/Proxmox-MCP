# Quick start

Production: follow [README.md: Setup](README.md#setup). The planner prints every step:

```sh
cp deploy/provision.example.toml deploy/provision.toml
python3 deploy/plan.py deploy/provision.toml
```

Development, on a workstation against a lab cluster: follow
[README.md: Local development](README.md#local-development). Use a lab API token with few
privileges and keep `MCP_LOCAL_MODE=ro`.

Tests:

```sh
uv venv -q .venv -p 3.14
uv pip install -q -p .venv -e . pytest pytest-asyncio pytest-cov ruff
.venv/bin/pytest -q --no-cov
```
