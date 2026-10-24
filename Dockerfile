# Proxmox MCP broker: Linux lab and CI image.
#
# The supported production host is Windows Server 2025 (docs/RUNBOOK.md). This
# image exists so that CI can build the package and so that a lab can run the
# broker on Linux. It holds no secret and reads no .env file.
#
# Runtime contract:
#   - credentials: mount a directory read-only at /run/credentials/proxmox-mcp with
#     enrollment.json, pve-token-<name> and worker-identity.pub, owned by uid 10001,
#     mode 0400;
#   - settings: environment variables from .env.example (no secrets);
#   - network: the broker binds 127.0.0.1 inside the container. Run cloudflared in
#     the same network namespace. Publish no port.
#
# Based on the upstream image of ry-ops/proxmox-mcp-server (MIT).
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Proxmox MCP broker"
LABEL org.opencontainers.image.description="On-premises broker for Proxmox VE behind Cloudflare Access (fork of ry-ops/proxmox-mcp-server)"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CREDENTIALS_DIRECTORY=/run/credentials/proxmox-mcp \
    MCP_AUDIT_LOG=/var/log/proxmox-mcp/audit.jsonl \
    MCP_BIND=127.0.0.1 \
    MCP_PORT=8765

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY proxmox_mcp ./proxmox_mcp

RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin broker \
    && install -d -o 10001 -g 10001 -m 0700 /var/log/proxmox-mcp

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/healthz', timeout=3).read() == b'ok' else 1)"]

CMD ["proxmox-mcp-http"]
