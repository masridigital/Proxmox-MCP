"""Network-facing half of the in-process guard (Streamable HTTP behind Cloudflare Access).

Kept import-light on purpose: ``server`` imports the constant below, and
``http_app`` imports ``server``, so nothing here may import either of them.
"""

# Key under which the HTTP guard stores the authenticated Identity in the ASGI
# scope. server.py reads it back from the request the MCP SDK attaches to every
# message, so the identity a tool runs as is always the one verified for that
# exact HTTP request, never one inherited through a long-lived task context.
IDENTITY_SCOPE_KEY = "proxmox_mcp.identity"
