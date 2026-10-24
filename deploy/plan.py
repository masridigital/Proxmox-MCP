#!/usr/bin/env python3
"""Validate a deployment file and print the ordered provisioning plan.

    python3 deploy/plan.py deploy/provision.toml            human-readable steps
    python3 deploy/plan.py deploy/provision.toml --json     the same plan for an AI agent
    python3 deploy/plan.py deploy/provision.toml --env      shell exports for provision.sh

Standard library only (Python 3.11 or later, for tomllib). It never contacts a host and never
reads or prints a secret: every secret in the plan is entered at a hidden prompt or piped from
host to host by the operator (AGENTS.md rule 2).

Each step names:
  where     mac (operator workstation) | proxmox (node shell) | broker (elevated PowerShell)
            | cloudflare (dashboard or API) | claude (the client)
  runner    agent  = an AI agent may run it when it has an approved shell on that host
            human  = a person runs it (it handles a secret, or needs a human decision)
  secret    true when the step creates or carries a secret. An agent never runs these steps,
            never captures their output and never asks for the secret.
  verify    what must be true before the next step
Exit codes: 0 plan printed, 2 the file is invalid (every problem is listed).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import tomllib

HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-fA-F]{64}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
HOST = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
)
IPV4 = re.compile(r"(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}")
CIDR4 = re.compile(IPV4.pattern + r"/(3[0-2]|[12]?\d)")
FINGERPRINT = re.compile(r"([0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}")
SSH = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+")
EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+")
SHORT = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
SLUG = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]")
TEAM = re.compile(r"https://([a-z0-9-]+)\.cloudflareaccess\.com")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
VERSION = re.compile(r"\d{4}\.\d{1,2}\.\d{1,3}")
STORAGE = re.compile(r"[a-z0-9]{3,24}")
CONTAINER = re.compile(r"[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]")
FILE = re.compile(r"[A-Za-z0-9._-]{1,128}")
CUSTODIAN = re.compile(r"[A-Za-z0-9 ._-]{2,64}")
PLACEHOLDER_IDS = {"0" * 32, "00000000-0000-0000-0000-000000000000", "0" * 64}
MODES = ("ro", "operator", "rw")


class Invalid(Exception):
    pass


@dataclass
class Step:
    id: str
    phase: str
    title: str
    where: str
    runner: str
    secret: bool
    commands: list[str]
    verify: str
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- validation


class Checker:
    def __init__(self, doc: dict[str, Any]) -> None:
        self.doc = doc
        self.problems: list[str] = []

    def get(
        self,
        section: str,
        key: str,
        kind: type,
        pattern: re.Pattern[str] | None = None,
        *,
        allow_empty: bool = False,
        placeholder_ok: bool = False,
    ) -> Any:
        sec = self.doc.get(section)
        if not isinstance(sec, dict) or key not in sec:
            self.problems.append(f"[{section}] {key}: missing")
            return None
        value = sec[key]
        if kind is bool:
            ok = isinstance(value, bool)
        elif kind is int:
            ok = isinstance(value, int) and not isinstance(value, bool)
        else:
            ok = isinstance(value, kind)
        if not ok:
            self.problems.append(f"[{section}] {key}: expected {kind.__name__}")
            return None
        if isinstance(value, str):
            if value == "" and allow_empty:
                return value
            if pattern is not None and not pattern.fullmatch(value):
                self.problems.append(f"[{section}] {key}: invalid value")
                return None
            if not placeholder_ok and value in PLACEHOLDER_IDS:
                self.problems.append(f"[{section}] {key}: still the example placeholder")
        return value

    def unknown_keys(self, allowed: dict[str, set[str]]) -> None:
        for section, value in self.doc.items():
            if section not in allowed:
                self.problems.append(f"unknown section [{section}]")
                continue
            entries = value if isinstance(value, list) else [value]
            for entry in entries:
                if isinstance(entry, dict):
                    for key in entry:
                        if key not in allowed[section]:
                            self.problems.append(f"[{section}] unknown key {key!r}")


SCHEMA = {
    "deployment": {
        "name",
        "broker_mode",
        "phi_in_scope",
        "baa_cloudflare_signed",
        "baa_anthropic_signed",
    },
    "proxmox": {
        "host",
        "port",
        "tls_fingerprint",
        "pool",
        "ssh",
        "node_audit",
        "node_syslog",
        "token_ttl_days",
    },
    "broker": {"hostname", "ssh", "port", "proxmox_addresses", "staging_dir", "allow_admin_tools"},
    "artifacts": {
        "python_installer",
        "python_sha256",
        "cloudflared_msi",
        "cloudflared_version",
        "cloudflared_sha256",
        "winsw_exe",
        "winsw_sha256",
    },
    "cloudflare": {
        "account_id",
        "zone_id",
        "team_domain",
        "idp_id",
        "worker_hostname",
        "broker_hostname",
        "portal_id",
        "server_id",
        "audit_bucket",
        "require_mfa",
    },
    "audit_shipping": {"storage_account", "container"},
    "escrow": {"custodian_a", "custodian_b"},
    "users": {"email", "short", "mode"},
}


def load(path: Path, *, allow_placeholders: bool = False) -> dict[str, Any]:
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise Invalid(f"cannot read {path}: {exc}") from None
    c = Checker(doc)
    c.unknown_keys(SCHEMA)
    po = allow_placeholders
    cfg: dict[str, Any] = {
        "name": c.get("deployment", "name", str, re.compile(r"[A-Za-z0-9 ._-]{1,64}")),
        "broker_mode": c.get("deployment", "broker_mode", str, re.compile("access|vpc")),
        "phi": c.get("deployment", "phi_in_scope", bool),
        "baa_cf": c.get("deployment", "baa_cloudflare_signed", str, DATE, allow_empty=True),
        "baa_anthropic": c.get("deployment", "baa_anthropic_signed", str, DATE, allow_empty=True),
        "pve_host": c.get("proxmox", "host", str, re.compile(f"{HOST.pattern}|{IPV4.pattern}")),
        "pve_port": c.get("proxmox", "port", int),
        "pve_pin": c.get("proxmox", "tls_fingerprint", str, FINGERPRINT, allow_empty=True),
        "pool": c.get("proxmox", "pool", str, re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,39}")),
        "pve_ssh": c.get("proxmox", "ssh", str, SSH),
        "node_audit": c.get("proxmox", "node_audit", bool),
        "node_syslog": c.get("proxmox", "node_syslog", bool),
        "ttl": c.get("proxmox", "token_ttl_days", int),
        "broker_host": c.get("broker", "hostname", str, HOST),
        "broker_ssh": c.get("broker", "ssh", str, SSH, allow_empty=True),
        "broker_port": c.get("broker", "port", int),
        "pve_cidrs": c.get("broker", "proxmox_addresses", list),
        "staging": c.get(
            "broker", "staging_dir", str, re.compile(r"[A-Za-z]:\\[A-Za-z0-9 ._\\-]{1,200}")
        ),
        "admin_tools": c.get("broker", "allow_admin_tools", bool),
        "py_exe": c.get(
            "artifacts", "python_installer", str, re.compile(r"python-\d+\.\d+\.\d+-amd64\.exe")
        ),
        "py_sha": c.get("artifacts", "python_sha256", str, HEX64, placeholder_ok=po),
        "cfd_msi": c.get("artifacts", "cloudflared_msi", str, FILE),
        "cfd_ver": c.get("artifacts", "cloudflared_version", str, VERSION),
        "cfd_sha": c.get("artifacts", "cloudflared_sha256", str, HEX64, placeholder_ok=po),
        "winsw_exe": c.get("artifacts", "winsw_exe", str, FILE),
        "winsw_sha": c.get("artifacts", "winsw_sha256", str, HEX64, placeholder_ok=po),
        "account_id": c.get("cloudflare", "account_id", str, HEX32, placeholder_ok=po),
        "zone_id": c.get("cloudflare", "zone_id", str, HEX32, placeholder_ok=po),
        "team_domain": c.get("cloudflare", "team_domain", str, TEAM),
        "idp_id": c.get("cloudflare", "idp_id", str, UUID, placeholder_ok=po),
        "worker_host": c.get("cloudflare", "worker_hostname", str, HOST),
        "broker_hostname": c.get("cloudflare", "broker_hostname", str, HOST, allow_empty=True),
        "portal_id": c.get("cloudflare", "portal_id", str, SLUG),
        "server_id": c.get("cloudflare", "server_id", str, SLUG),
        "bucket": c.get("cloudflare", "audit_bucket", str, BUCKET),
        "require_mfa": c.get("cloudflare", "require_mfa", bool),
        "storage_account": c.get("audit_shipping", "storage_account", str, STORAGE),
        "container": c.get("audit_shipping", "container", str, CONTAINER),
        "custodian_a": c.get("escrow", "custodian_a", str, CUSTODIAN),
        "custodian_b": c.get("escrow", "custodian_b", str, CUSTODIAN),
    }
    # Cross-field rules.
    if isinstance(cfg["pve_port"], int) and not 1 <= cfg["pve_port"] <= 65535:
        c.problems.append("[proxmox] port: 1-65535")
    if isinstance(cfg["broker_port"], int) and not 1024 <= cfg["broker_port"] <= 65535:
        c.problems.append("[broker] port: 1024-65535")
    if isinstance(cfg["ttl"], int) and not 1 <= cfg["ttl"] <= 365:
        c.problems.append("[proxmox] token_ttl_days: 1-365")
    if isinstance(cfg["pve_cidrs"], list):
        if not cfg["pve_cidrs"] or not all(
            isinstance(x, str) and CIDR4.fullmatch(x) for x in cfg["pve_cidrs"]
        ):
            c.problems.append("[broker] proxmox_addresses: one or more IPv4 CIDRs")
    if cfg["broker_mode"] == "access" and not cfg["broker_hostname"]:
        c.problems.append("[cloudflare] broker_hostname: required in access mode")
    if cfg["broker_hostname"] and cfg["broker_hostname"] == cfg["worker_host"]:
        c.problems.append("[cloudflare] broker_hostname must differ from worker_hostname")
    if cfg["custodian_a"] and cfg["custodian_a"] == cfg["custodian_b"]:
        c.problems.append("[escrow] the two custodians must be different people")
    if cfg["phi"] and not (cfg["baa_cf"] and cfg["baa_anthropic"]):
        c.problems.append("[deployment] phi_in_scope = true needs both BAA dates (go-live gate)")

    users = doc.get("users")
    cfg["users"] = []
    if not isinstance(users, list) or not users:
        c.problems.append("[[users]]: at least one person")
    else:
        seen_email: set[str] = set()
        seen_short: set[str] = set()
        for i, u in enumerate(users):
            if not isinstance(u, dict):
                c.problems.append(f"[[users]] #{i + 1}: must be a table")
                continue
            email, short, mode = u.get("email"), u.get("short"), u.get("mode")
            if not (isinstance(email, str) and EMAIL.fullmatch(email)):
                c.problems.append(f"[[users]] #{i + 1}: email must be a lowercase ASCII address")
            if not (isinstance(short, str) and SHORT.fullmatch(short) and short != "root"):
                c.problems.append(
                    f"[[users]] #{i + 1}: short must match ^[a-z0-9][a-z0-9-]{{0,30}}$, not root"
                )
            if mode not in MODES:
                c.problems.append(f"[[users]] #{i + 1}: mode must be ro, operator or rw")
            if mode == "rw" and not cfg["admin_tools"]:
                c.problems.append(f"[[users]] #{i + 1}: rw needs [broker] allow_admin_tools = true")
            if email in seen_email or short in seen_short:
                c.problems.append(
                    f"[[users]] #{i + 1}: one person, one key: email and short must be unique"
                )
            seen_email.add(email)
            seen_short.add(short)
            cfg["users"].append({"email": email, "short": short, "mode": mode})
    if c.problems:
        raise Invalid("\n".join(f"  - {p}" for p in c.problems))
    m = TEAM.fullmatch(cfg["team_domain"])
    cfg["team_name"] = m.group(1) if m else ""
    return cfg


# --------------------------------------------------------------------------- plan


def ps_path(staging: str, name: str) -> str:
    return f"{staging}\\{name}"


def build_plan(c: dict[str, Any]) -> list[Step]:
    s: list[Step] = []
    setup = "deploy/proxmox/setup-proxmox-access.sh"
    pve_env = (
        f"MCP_POOL={c['pool']} NODE_AUDIT={int(c['node_audit'])} "
        f"NODE_SYSLOG={int(c['node_syslog'])} TOKEN_TTL_DAYS={c['ttl']}"
    )
    scripts = r"C:\Program Files\ProxmoxMCP\scripts"
    pin = c["pve_pin"] or "<tls_fingerprint from step proxmox-pin>"
    access = c["broker_mode"] == "access"

    s.append(
        Step(
            "gates",
            "0 preflight",
            "Confirm the go-live gates",
            "mac",
            "human",
            False,
            [
                "Confirm a change approval (ticket) for this deployment.",
                "Confirm the IdP enforces MFA for the Access application (Conditional Access or equal).",
                "If [deployment] phi_in_scope is true: confirm the BAAs with Cloudflare and Anthropic are signed.",
            ],
            "The approver, the MFA policy and (if PHI) both BAA dates are recorded in the change ticket.",
        )
    )

    s.append(
        Step(
            "build",
            "1 build",
            "Build and hash the release",
            "mac",
            "agent",
            False,
            [
                "uv build --wheel",
                "python3 requirements/generate_broker_lock.py --check",
                "shasum -a 256 dist/proxmox_mcp_server-*.whl requirements/broker-win.txt",
                "cd worker && npm ci --ignore-scripts && npm test && cd ..",
            ],
            "CI is green on the commit, the lock check passes, the hashes are recorded in the ticket.",
            [
                f"Download {c['py_exe']}, {c['cfd_msi']} ({c['cfd_ver']}) and {c['winsw_exe']}; check each "
                "SHA-256 against [artifacts] from a second network."
            ],
        )
    )

    s.append(
        Step(
            "proxmox-roles",
            "2 proxmox",
            "Create the pool and the ProxmoxMCP roles",
            "proxmox",
            "agent",
            False,
            [
                f"ssh {c['pve_ssh']} '{pve_env} DRY_RUN=1 bash -s -- roles' < {setup}",
                f"ssh {c['pve_ssh']} '{pve_env} bash -s -- roles' < {setup}",
            ],
            f"`pveum role list` shows ProxmoxMCP-*; then a human moves only the guests in scope into pool {c['pool']}.",
        )
    )

    for u in c["users"]:
        s.append(
            Step(
                f"proxmox-user-{u['short']}",
                "2 proxmox",
                f"Proxmox user for {u['email']}",
                "proxmox",
                "agent",
                False,
                [
                    f"ssh {c['pve_ssh']} '{pve_env} bash -s -- user {u['short']} {u['mode']}' < {setup}",
                ],
                f"mcp-{u['short']}@pve exists with ACLs only on /pool/{c['pool']} (and /nodes if node_audit).",
            )
        )

    s.append(
        Step(
            "proxmox-pin",
            "2 proxmox",
            "Read the API certificate pin",
            "proxmox",
            "agent",
            False,
            [
                f"ssh {c['pve_ssh']} 'openssl x509 -in /etc/pve/local/pveproxy-ssl.pem -noout -fingerprint -sha256 2>/dev/null"
                " || openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256'",
            ],
            "Write the value (without the 'sha256 Fingerprint=' prefix) to [proxmox] tls_fingerprint and re-run the plan.",
        )
    )

    s.append(
        Step(
            "broker-baseline",
            "3 broker",
            "Harden the broker host",
            "broker",
            "agent",
            False,
            [
                f"cd '{c['staging']}'",
                r".\Set-BrokerHostBaseline.ps1 -WhatIf",
                r".\Set-BrokerHostBaseline.ps1",
            ],
            "BitLocker (TPM) and Windows LAPS are on (a human confirms); the host is rebooted.",
            [
                f"Copy deploy\\windows\\*, the wheel, requirements\\broker-win.txt and the three downloads to {c['staging']}."
            ],
        )
    )

    install = (
        rf".\Install-ProxmoxMcpBroker.ps1 -PythonInstaller .\{c['py_exe']} -PythonSha256 {c['py_sha']} "
        r"-WheelPath .\<wheel> -WheelSha256 <wheel sha256> "
        r"-RequirementsLock .\broker-win.txt -RequirementsLockSha256 <lock sha256> "
        rf"-WinSWPath .\{c['winsw_exe']} -WinSWSha256 {c['winsw_sha']} "
        f"-ProxmoxHost {c['pve_host']} -ProxmoxPort {c['pve_port']} -ProxmoxTlsFingerprint {pin} "
        f"-BrokerPort {c['broker_port']}" + (" -AllowAdminTools" if c["admin_tools"] else "")
    )
    s.append(
        Step(
            "broker-install",
            "3 broker",
            "Install the broker (first pass)",
            "broker",
            "agent",
            False,
            [
                f"cd '{c['staging']}'",
                install + " -WhatIf",
                install,
                rf".\Install-Cloudflared.ps1 -MsiPath .\{c['cfd_msi']} -MsiSha256 {c['cfd_sha']} -Version {c['cfd_ver']}",
                rf".\Set-BrokerFirewall.ps1 -ProxmoxAddress {','.join(c['pve_cidrs'])} -BrokerMode {c['broker_mode']}"
                + (" -FetchCloudflareRanges" if access else "")
                + " -WhatIf",
                rf".\Set-BrokerFirewall.ps1 -ProxmoxAddress {','.join(c['pve_cidrs'])} -BrokerMode {c['broker_mode']}"
                + (" -FetchCloudflareRanges" if access else ""),
            ],
            "Services ProxmoxMCPBroker and cloudflared-proxmox-mcp exist; the first pass leaves the broker unreachable "
            "until the Cloudflare step and the second pass.",
        )
    )

    for u in c["users"]:
        to_broker = (
            f' | ssh {c["broker_ssh"]} "powershell.exe -NoProfile -NonInteractive -File '
            f"'{scripts}\\Protect-BrokerCredential.ps1' -Name pve-token-{u['short']} -Force\""
            if c["broker_ssh"]
            else ""
        )
        cmd = f"ssh {c['pve_ssh']} '{pve_env} bash -s -- issue-token {u['short']} {u['mode']}' < {setup}{to_broker}"
        notes = [
            "The secret goes from the Proxmox node straight into the broker's DPAPI store. Never print, "
            "save or paste it anywhere else."
        ]
        if not c["broker_ssh"]:
            notes.append(
                f"No [broker] ssh: run the command, then on the broker run "
                f"'{scripts}\\Protect-BrokerCredential.ps1' -Name pve-token-{u['short']} -Force "
                "and paste the one line at its hidden prompt. Clear the clipboard."
            )
        s.append(
            Step(
                f"token-{u['short']}",
                "4 credentials",
                f"Proxmox API token for {u['email']}",
                "proxmox",
                "human",
                True,
                [cmd],
                "The node log line 'token_expires=YYYY-MM-DD' is recorded for the next step.",
                notes,
            )
        )
        s.append(
            Step(
                f"enroll-{u['short']}",
                "4 credentials",
                f"Enroll {u['email']}",
                "broker",
                "agent",
                False,
                [
                    rf".\Set-BrokerEnrollment.ps1 -Email {u['email']} -Mode {u['mode']} "
                    f"-ProxmoxUserId mcp-{u['short']}@pve -TokenExpires <token_expires>",
                ],
                f"`.\\Set-BrokerEnrollment.ps1 -List` shows {u['email']} with mode {u['mode']}.",
            )
        )

    s.append(
        Step(
            "cloudflare",
            "5 cloudflare",
            "Provision Cloudflare (tunnel, Access, Worker, R2, portal)",
            "mac",
            "human",
            True,
            [
                'eval "$(python3 deploy/plan.py deploy/provision.toml --env)"',
                "read -r -s CF_API_TOKEN; export CF_API_TOKEN",
                "DRY_RUN=1 ./deploy/cloudflare/provision.sh",
                "./deploy/cloudflare/provision.sh",
                "STEPS=worker DEPLOY_WORKER=1 ./deploy/cloudflare/provision.sh",
            ],
            f"~/.proxmox-mcp/{c['worker_host']}.json holds tunnel_id, worker_aud"
            + (", broker_aud, service_token_client_id" if access else ", vpc_service_id")
            + "; delete the API token after go-live.",
            [
                "The API token, tunnel token, service-token secret and Worker signing key never leave the "
                "operator's terminal, wrangler and the broker. An agent may read the state file (ids only)."
            ],
        )
    )

    second = (
        install
        + f" -BrokerMode {c['broker_mode']}"
        + (
            f" -BrokerHostHeader {c['broker_hostname']} -CfAccessTeamDomain {c['team_domain']} "
            "-BrokerAccessAud <broker_aud> -BrokerServiceClientIds <service_token_client_id>"
            if access
            else ""
        )
        + " -Start"
    )
    s.append(
        Step(
            "broker-activate",
            "6 activate",
            "Install the broker (second pass) and start it",
            "broker",
            "agent",
            False,
            [
                f"cd '{c['staging']}'",
                second + " -WhatIf",
                second,
                r".\Invoke-BrokerSelfCheck.ps1 -Register",
            ],
            "`.\\Test-ProxmoxMcpBroker.ps1` shows no FAIL.",
            ["Values in <...> come from the state file of step cloudflare (ids, not secrets)."],
        )
    )

    s.append(
        Step(
            "escrow",
            "6 activate",
            "Escrow the audit HMAC key with two custodians",
            "broker",
            "human",
            True,
            [
                rf".\Export-AuditKeyEscrow.ps1 -ShareAPath E:\audit-key-share-A.txt -ShareBPath F:\audit-key-share-B.txt "
                f'-CustodianA "{c["custodian_a"]}" -CustodianB "{c["custodian_b"]}"',
            ],
            "Each custodian holds one share in a separate safe; the evidence file is in the ticket.",
            [
                "Two removable drives, never the system volume. Custodians are not broker administrators."
            ],
        )
    )

    s.append(
        Step(
            "audit-shipping",
            "6 activate",
            "Ship the audit log to immutable storage",
            "broker",
            "human",
            True,
            [
                rf".\Send-AuditLog.ps1 -Register -StorageAccount {c['storage_account']} -Container {c['container']}",
                r".\Protect-BrokerCredential.ps1 -Name audit-ship-sas -Reader System",
                r".\Send-AuditLog.ps1 -TestImmutability -AdminCheck",
            ],
            "Overwrite and delete return 409/403; the evidence file is in the ticket.",
            [
                "Before: create the container with a locked 2190-day retention policy and a SAS with sp=c, "
                "spr=https, expiry at most one year. Paste the SAS only at the hidden prompt."
            ],
        )
    )

    s.append(
        Step(
            "verify",
            "7 verify",
            "Go-live checks",
            "broker",
            "agent",
            False,
            [
                r".\Test-ProxmoxMcpBroker.ps1 -Baseline -Live",
                f"curl -s -o /dev/null -w '%{{http_code}}\\n' -X POST https://{c['worker_host']}/mcp   # from any host: 401",
            ],
            "No FAIL; unauthenticated POST answers 401 with WWW-Authenticate.",
            [
                "A human also runs `STEPS=verify ./deploy/cloudflare/provision.sh` (it needs the API token)."
            ],
        )
    )

    s.append(
        Step(
            "connect",
            "7 verify",
            "Connect Claude and run one read",
            "claude",
            "human",
            False,
            [
                f"In the MCP portal (id {c['portal_id']}), enable server {c['server_id']}; sign in; ask: list my Proxmox nodes.",
            ],
            "One allowed read; the broker audit log shows the user, the tool and status ok.",
        )
    )
    return s


def env_exports(c: dict[str, Any]) -> list[str]:
    def q(v: Any) -> str:
        return "'" + str(v).replace("'", "'\\''") + "'"

    pairs = {
        "ACCOUNT_ID": c["account_id"],
        "ZONE_ID": c["zone_id"],
        "WORKER_HOSTNAME": c["worker_host"],
        "TEAM_DOMAIN": c["team_domain"],
        "IDP_ID": c["idp_id"],
        "ALLOWED_EMAILS": ",".join(u["email"] for u in c["users"]),
        "PORTAL_ID": c["portal_id"],
        "SERVER_ID": c["server_id"],
        "WORKER_DIR": "./worker",
        "AUDIT_BUCKET": c["bucket"],
        "BROKER_MODE": c["broker_mode"],
        "ORIGIN_PORT": c["broker_port"],
        "REQUIRE_MFA": int(c["require_mfa"]),
    }
    if c["broker_mode"] == "access":
        pairs["BROKER_HOSTNAME"] = c["broker_hostname"]
    if c["broker_ssh"]:
        pairs["BROKER_SSH"] = c["broker_ssh"]
    return [f"export {k}={q(v)}" for k, v in pairs.items()]


def render_text(steps: list[Step]) -> str:
    out: list[str] = []
    phase = ""
    for i, st in enumerate(steps, 1):
        if st.phase != phase:
            phase = st.phase
            out.append(f"\n== {phase} ==")
        tag = "HUMAN, SECRET" if st.secret else st.runner.upper()
        out.append(f"\n{i:>2}. [{st.id}] {st.title}   ({st.where}; {tag})")
        out += [f"      {line}" for line in st.commands]
        out += [f"      note: {n}" for n in st.notes]
        out.append(f"      verify: {st.verify}")
    return "\n".join(out).lstrip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("file", type=Path)
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="machine-readable plan for an AI agent")
    fmt.add_argument(
        "--env", action="store_true", help="shell exports for deploy/cloudflare/provision.sh"
    )
    ap.add_argument(
        "--allow-placeholders",
        action="store_true",
        help="accept the all-zero example ids (for reviewing the example file only)",
    )
    args = ap.parse_args(argv)
    try:
        cfg = load(args.file, allow_placeholders=args.allow_placeholders)
    except Invalid as exc:
        print(f"{args.file}: invalid deployment file\n{exc}", file=sys.stderr)
        return 2
    if args.env:
        print("\n".join(env_exports(cfg)))
        return 0
    steps = build_plan(cfg)
    if args.json:
        print(
            json.dumps(
                {
                    "deployment": cfg["name"],
                    "broker_mode": cfg["broker_mode"],
                    "steps": [asdict(st) for st in steps],
                },
                indent=2,
            )
        )
    else:
        print(render_text(steps), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
