#!/usr/bin/env bash
# Connection check without secrets.
#
# 1. The Proxmox certificate fingerprint equals PROXMOX_TLS_FINGERPRINT.
# 2. The broker answers /healthz with "ok" on loopback.
# 3. The broker refuses /v1/catalog without credentials (HTTP 401).
#
# This script sends no token and reads no credential file. To test a person's
# access, use Claude through the MCP portal and read the audit log.
# The upstream version sent tokens or passwords with "curl -k"; that is removed.
#
# Usage: PROXMOX_HOST=pve.example.internal PROXMOX_TLS_FINGERPRINT=<hex> ./test-connection.sh
# Windows broker host: see docs/RUNBOOK.md for the PowerShell checks.
set -euo pipefail

PROXMOX_PORT="${PROXMOX_PORT:-8006}"
MCP_PORT="${MCP_PORT:-8765}"
status=0

norm() { tr -d ':[:space:]' | tr '[:upper:]' '[:lower:]'; }

if [[ -n "${PROXMOX_HOST:-}" && -n "${PROXMOX_TLS_FINGERPRINT:-}" ]]; then
  actual=$(openssl s_client -connect "${PROXMOX_HOST}:${PROXMOX_PORT}" \
             -servername "${PROXMOX_HOST}" </dev/null 2>/dev/null \
           | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
           | sed 's/^.*=//' | norm || true)
  expected=$(printf '%s' "${PROXMOX_TLS_FINGERPRINT%%,*}" | norm)
  if [[ -n "$actual" && "$actual" == "$expected" ]]; then
    echo "ok    Proxmox certificate matches PROXMOX_TLS_FINGERPRINT"
  else
    echo "FAIL  Proxmox certificate does not match PROXMOX_TLS_FINGERPRINT (or no TLS connection)"
    status=1
  fi
else
  echo "skip  Proxmox TLS check (set PROXMOX_HOST and PROXMOX_TLS_FINGERPRINT)"
fi

health=$(curl -s --max-time 5 "http://127.0.0.1:${MCP_PORT}/healthz" || true)
if [[ "$health" == "ok" ]]; then
  echo "ok    broker /healthz on 127.0.0.1:${MCP_PORT}"
else
  echo "FAIL  broker /healthz on 127.0.0.1:${MCP_PORT} (is the service running?)"
  status=1
fi

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
         "http://127.0.0.1:${MCP_PORT}/v1/catalog" || true)
if [[ "$code" == "401" ]]; then
  echo "ok    broker refuses unauthenticated /v1/catalog (401)"
else
  echo "FAIL  broker answered ${code:-nothing} to unauthenticated /v1/catalog (expect 401)"
  status=1
fi

exit "$status"
