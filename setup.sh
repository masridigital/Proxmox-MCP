#!/usr/bin/env bash
# The upstream interactive setup is removed from this fork.
#
# It created a .env file with a shared Proxmox token or password and turned TLS
# verification off. The broker keeps one token per person in its credentials
# directory and always verifies the Proxmox certificate, so a script that writes
# secrets to .env is not safe here.
#
# Development environment:
#   uv venv -q .venv -p 3.12
#   uv pip install -q -p .venv -e . pytest pytest-asyncio pytest-cov ruff
#   .venv/bin/pytest -q --no-cov
#
# Broker installation: docs/RUNBOOK.md
set -euo pipefail

cat >&2 <<'MSG'
setup.sh: removed in this fork.
  Development: see README.md, section "Local development".
  Installation: see docs/RUNBOOK.md.
MSG
exit 1
