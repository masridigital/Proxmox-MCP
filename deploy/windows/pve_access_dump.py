"""Read-only Proxmox access dump for the quarterly access review (Export-AccessReview.ps1).

Run with the broker venv interpreter (the firewall allows only that interpreter to reach
Proxmox on 8006):

    venv\\Scripts\\python.exe -I pve_access_dump.py

Reads PROXMOX_HOST / PROXMOX_PORT / PROXMOX_TLS_FINGERPRINT / PROXMOX_CA_BUNDLE from the
environment (Export-AccessReview.ps1 sets them from broker.env) and the review token from
the broker credential store (credential "pve-review-token": user@pve!name=<uuid>, a token
with Sys.Audit on /access only). Prints one JSON document to stdout.

TLS: with a fingerprint, the certificate SHA-256 is compared BEFORE the token is sent.
With a CA bundle, normal chain and hostname checks apply. There is no insecure mode.
Only GET requests are made.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import ssl
import sys

from proxmox_mcp.credentials import parse_api_token, read_credential

PATHS = {
    "acl": "/api2/json/access/acl",
    "users": "/api2/json/access/users?full=1",
    "roles": "/api2/json/access/roles",
    "pools": "/api2/json/pools",
}


def _context() -> tuple[ssl.SSLContext, str | None]:
    pin = os.environ.get("PROXMOX_TLS_FINGERPRINT", "").replace(":", "").strip().lower()
    ca = os.environ.get("PROXMOX_CA_BUNDLE", "").strip()
    if pin:
        if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
            raise SystemExit("PROXMOX_TLS_FINGERPRINT is not a SHA-256 hex digest")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # replaced by the explicit pin check below
        return ctx, pin
    if ca:
        return ssl.create_default_context(cafile=ca), None
    raise SystemExit("set PROXMOX_TLS_FINGERPRINT or PROXMOX_CA_BUNDLE")


def main() -> int:
    host = os.environ.get("PROXMOX_HOST", "").strip()
    port = int(os.environ.get("PROXMOX_PORT", "8006"))
    if not host:
        raise SystemExit("PROXMOX_HOST is not set")
    ctx, pin = _context()
    token = parse_api_token(read_credential("pve-review-token"))
    out: dict[str, object] = {"host": host, "token_id": token.token_id}
    for key, path in PATHS.items():
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=30)
        try:
            conn.connect()
            if pin is not None:
                der = conn.sock.getpeercert(binary_form=True) if conn.sock else None
                got = hashlib.sha256(der or b"").hexdigest()
                if not hmac.compare_digest(got, pin):
                    raise SystemExit("Proxmox certificate does not match the pinned fingerprint")
            conn.request("GET", path, headers={"Authorization": token.header()})
            resp = conn.getresponse()
            body = resp.read(8 * 1024 * 1024)
            if resp.status != 200:
                out[key] = {"error": resp.status}
                continue
            out[key] = json.loads(body).get("data")
        finally:
            conn.close()
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
