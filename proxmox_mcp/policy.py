"""Inbound tool policy: which tool a caller may run, decided by tool tier and caller mode.

Tiers
-----
read       GET only, no secrets in the response beyond what output redaction handles.
operate    Reversible guest lifecycle: start / stop / shutdown / reboot / reset / suspend /
           resume of one VM or CT, and taking a snapshot. Nothing is lost by doing it.
admin      Destructive or config-changing work on guests and guest-level objects: create,
           clone, delete, set config, resize, move disks, rollback, guest firewall, pools,
           HA, replication, backup jobs, SDN, migration. Needs mode rw AND
           MCP_ALLOW_ADMIN_TOOLS=1.
forbidden  Human-only. Never available through MCP, whatever the mode: identity and
           permission changes, passwords, TFA, API tokens, consoles and shells, guest-agent
           exec, host power and host network, host disks, host firewall, TLS certificates
           (the broker pins the Proxmox certificate), storage definitions and volume deletion
           (backups), anything that carries a third-party secret through the model, anything
           that redirects or silences alerting, and (HIPAA/SOC 2) anything that reads or
           writes guest CONTENT: guest-agent exec/file/password, consoles, cloud-init
           user-data, and URL downloads into storage. Hypervisor metadata reads stay read.

Mode -> tiers:  ro: read.  operator: read + operate.  rw: read + operate + admin (with flag).

Every registered tool has an explicit entry in ``TOOL_TIERS`` (a test enforces it). The
table was built by tracing each ``handle()`` to the Proxmox method and path it calls; the
comment on each group says why. ``FORBIDDEN_RE`` is a name-based safety net: a match forces
``forbidden`` even if the table says otherwise. Unknown tools are ``forbidden``.

Tier consistency with the outbound policy: a tool whose handler sends anything but GET is
never ``read``, and a tool that sends DELETE is never below ``admin`` (DELETE needs rw).

Operator overrides (they can only restrict further):
  MCP_TOOL_DENY   comma-separated regexes; a tool whose name matches any of them is denied.
  MCP_TOOL_ALLOW  comma-separated exact tool names; when set, every other tool is denied.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
from typing import Any, Literal

from .enrollment import Enrollment, Mode, enrollment_for
from .identity import Identity

log = logging.getLogger(__name__)

Tier = Literal["read", "operate", "admin", "forbidden"]

R: Tier = "read"
O: Tier = "operate"  # noqa: E741
A: Tier = "admin"
F: Tier = "forbidden"

TOOL_TIERS: dict[str, Tier] = {
    # ------------------------------------------------------------------ nodes.py
    # Host inventory, status, logs and diagnostics: GET only.
    "list_nodes": R,
    "get_node_status": R,
    "get_node_config": R,
    "get_node_version": R,
    "get_node_time": R,
    "get_node_dns": R,
    "get_node_hosts": R,
    "get_node_network": R,
    "get_node_network_interface": R,
    "get_node_netstat": R,
    "list_node_services": R,
    "get_node_service_state": R,
    "get_node_syslog": R,
    "get_node_journal": R,
    "get_node_report": R,
    "get_node_subscription": R,
    "get_node_apt_update": R,  # GET /apt/update only lists pending updates; it does not refresh
    "get_node_apt_changelog": R,
    "get_node_hardware": R,
    "get_node_rrd": R,
    "get_node_rrddata": R,
    "get_node_aplinfo": R,
    "get_node_capabilities_qemu": R,
    "get_node_scan": R,  # GET /scan/{type}; no server/credential args are passed
    # Host configuration that is low-impact and reversible.
    "set_node_time": A,  # PUT /time: timezone only
    "revert_node_network": A,  # DELETE /network: discards pending (unapplied) changes
    "start_node_service": A,
    "restart_node_service": A,
    "reload_node_service": A,
    "node_startall": A,  # host-wide bulk start
    "node_migrateall": A,  # evacuates a host
    "wakeonlan": A,  # host power-on (POST /wakeonlan)
    # Host plane: can lock everyone out of the cluster or redirect its traffic. Human-only.
    "set_node_dns": F,
    "set_node_hosts": F,
    "apply_node_network": F,
    "stop_node_service": F,  # can stop pve-firewall, pveproxy, sshd
    "node_shutdown": F,  # POST /status command=shutdown|reboot of the host itself
    "node_stopall": F,
    # ------------------------------------------------------------------ qemu.py
    "list_vms": R,
    "get_vm_status": R,
    "get_vm_config": R,  # cipassword/sshkeys are redacted by output.py
    "get_vm_pending": R,
    "list_vm_snapshots": R,
    "get_vm_snapshot_config": R,
    "get_vm_migrate_preconditions": R,
    "get_vm_firewall_rules": R,
    "get_vm_firewall_options": R,
    "get_vm_firewall_log": R,
    "get_vm_rrddata": R,
    "get_vm_feature": R,
    # Guest-agent facts (filesystem list, NIC addresses, OS name/version) are hypervisor-style
    # metadata, not file contents or command output, so they stay read (COMPLIANCE review).
    "vm_agent_get_fsinfo": R,
    "vm_agent_get_network_interfaces": R,
    "vm_agent_get_osinfo": R,
    # Reversible lifecycle of one VM.
    "start_vm": O,
    "stop_vm": O,
    "shutdown_vm": O,
    "reboot_vm": O,
    "reset_vm": O,
    "suspend_vm": O,
    "resume_vm": O,
    "create_vm_snapshot": O,  # additive; nothing is lost
    "vm_agent_ping": O,  # harmless, but it is a POST, so not read
    # Destructive or config-changing on a VM.
    "set_vm_config": A,
    "create_vm": A,  # extra_config passes arbitrary config keys to Proxmox
    "clone_vm": A,
    "delete_vm": A,
    "convert_vm_to_template": A,  # irreversible
    "rollback_vm_snapshot": A,  # discards current state
    "delete_vm_snapshot": A,
    "migrate_vm": A,  # see note below
    "resize_vm_disk": A,  # grow-only but irreversible
    "move_vm_disk": A,  # can delete the source disk
    "unlink_vm_disk": A,  # force=1 destroys the disk
    "import_vm_disk": A,  # builds a disk spec from caller strings (options appended raw)
    "add_vm_firewall_rule": A,
    "delete_vm_firewall_rule": A,
    "set_vm_firewall_options": A,
    # Guest CONTENT (HIPAA minimum necessary, SOC 2 C1): anything that reads or writes what is
    # inside a guest, or a console onto it, is human-only. The router also refuses
    # cipassword/password keys in create_vm extra_config and create_container.
    "get_vm_cloudinit": F,  # GET cloudinit/dump: user-data with password hash, keys, scripts
    "regenerate_vm_cloudinit": F,  # writes the cloud-init drive the guest consumes
    # Code execution, credentials and consoles inside or onto the guest. Human-only.
    "vm_agent_exec": F,
    "vm_agent_exec_status": F,  # returns stdout/stderr of guest commands (guest content)
    "vm_agent_set_user_password": F,
    "get_vm_vnc_proxy": F,  # console ticket
    "get_vm_spice_proxy": F,  # console ticket
    # Migration is admin, not operate: it moves the guest and possibly its disks to another
    # host, consumes capacity there, and offline/restart migration causes downtime. It is not
    # a lifecycle toggle a read-mostly operator needs.
    # ------------------------------------------------------------------ lxc.py
    "list_containers": R,
    "get_container_status": R,
    "get_container_config": R,
    "get_container_pending": R,
    "list_container_snapshots": R,
    "get_container_firewall_rules": R,
    "get_container_firewall_options": R,
    "get_container_rrddata": R,
    "start_container": O,
    "stop_container": O,
    "shutdown_container": O,
    "reboot_container": O,
    "suspend_container": O,
    "resume_container": O,
    "create_container_snapshot": O,
    "set_container_config": A,
    "create_container": A,
    "clone_container": A,
    "delete_container": A,
    "resize_container_disk": A,
    "move_container_disk": A,
    "migrate_container": A,
    "rollback_container_snapshot": A,
    "delete_container_snapshot": A,
    "add_container_firewall_rule": A,
    "delete_container_firewall_rule": A,
    "set_container_firewall_options": A,
    "convert_container_to_template": A,
    # ------------------------------------------------------------------ storage.py
    "list_storage": R,
    "get_storage_config": R,
    "get_node_storage_status": R,
    "list_storage_content": R,
    "get_storage_volume_info": R,
    "update_storage": A,  # cluster storage options (content, nodes, disable)
    "copy_storage_volume": A,
    "backup_vm": A,  # vzdump: remove/prune-backups can delete old backups; mailto
    "restore_vm_backup": A,  # force=1 overwrites an existing VM
    "restore_container_backup": A,
    # Storage definitions and volume deletion destroy data or backups (ransomware pattern),
    # and create_storage carries remote-storage passwords and can mount an outside share.
    "create_storage": F,
    # The PVE host fetches a caller-chosen URL (SSRF into the LAN) and writes the file into
    # storage as ISO/template/import content that guests boot from.
    "download_url_to_storage": F,
    "delete_storage": F,
    "delete_storage_volume": F,
    # ------------------------------------------------------------------ cluster.py
    "get_cluster_status": R,
    "get_cluster_resources": R,
    "get_cluster_version": R,
    "get_cluster_nextid": R,
    "get_cluster_options": R,
    "get_cluster_log": R,
    "list_cluster_tasks": R,
    "list_node_tasks": R,
    "get_task_status": R,
    "get_task_log": R,
    "list_ha_resources": R,
    "get_ha_resource": R,
    "list_ha_groups": R,
    "get_ha_status": R,
    "list_replication_jobs": R,
    "get_replication_job": R,
    "list_backup_jobs": R,
    "get_backup_job": R,
    "list_metrics_servers": R,
    "list_realm_sync_jobs": R,
    "analyze_schedule": R,  # pure computation; GET /cluster/jobs/schedule-analyze
    "set_cluster_options": A,
    "stop_task": A,  # DELETE /tasks/{upid}; can abort a running backup
    "add_ha_resource": A,
    "update_ha_resource": A,
    "delete_ha_resource": A,
    "create_replication_job": A,
    "update_replication_job": A,
    "delete_replication_job": A,
    "create_backup_job": A,
    "update_backup_job": A,
    "delete_backup_job": A,
    "bulk_start_guests": A,  # cluster-wide blast radius
    "bulk_shutdown_guests": A,
    "bulk_migrate_guests": A,
    # External metrics: carries a token through the model and ships data to a chosen server;
    # deleting one blinds monitoring.
    "create_metrics_server": F,
    "delete_metrics_server": F,
    # ------------------------------------------------------------------ access.py
    # Reading users, groups, roles, ACLs and realms is inventory.
    "list_users": R,
    "get_user": R,
    "list_groups": R,
    "get_group": R,
    "list_roles": R,
    "get_role": R,
    "get_acl": R,
    "list_auth_domains": R,
    "get_auth_domain": R,
    # Identity, permission, password, token and TFA changes are human-only. Token and TFA
    # reads are also forbidden: those paths are on the outbound area deny list.
    "create_user": F,
    "update_user": F,
    "delete_user": F,
    "change_user_password": F,
    "list_user_tokens": F,
    "get_user_token": F,
    "create_user_token": F,
    "update_user_token": F,
    "delete_user_token": F,
    "create_group": F,
    "update_group": F,
    "delete_group": F,
    "create_role": F,
    "update_role": F,
    "delete_role": F,
    "update_acl": F,
    "create_auth_domain": F,
    "update_auth_domain": F,
    "delete_auth_domain": F,
    "sync_auth_domain": F,
    "list_tfa": F,
    "get_user_tfa": F,
    "add_tfa": F,
    "delete_tfa": F,
    # ------------------------------------------------------------------ firewall.py
    "list_cluster_firewall_rules": R,
    "get_cluster_firewall_options": R,
    "list_firewall_groups": R,
    "list_firewall_group_rules": R,
    "list_firewall_aliases": R,
    "list_firewall_ipsets": R,
    "list_firewall_ipset_entries": R,
    "list_node_firewall_rules": R,
    "get_node_firewall_options": R,
    "get_node_firewall_log": R,
    "get_cluster_firewall_log": R,
    "list_firewall_macros": R,
    "list_firewall_refs": R,
    # The cluster and host firewall protect the management plane this broker itself uses.
    # Any rule, option, group, alias or ipset change there can open it or disable it.
    # Guest-level firewall changes are admin (qemu.py / lxc.py above).
    "add_cluster_firewall_rule": F,
    "update_cluster_firewall_rule": F,
    "delete_cluster_firewall_rule": F,
    "set_cluster_firewall_options": F,
    "create_firewall_group": F,
    "delete_firewall_group": F,
    "add_firewall_group_rule": F,
    "delete_firewall_group_rule": F,
    "create_firewall_alias": F,
    "update_firewall_alias": F,
    "delete_firewall_alias": F,
    "create_firewall_ipset": F,
    "delete_firewall_ipset": F,
    "add_firewall_ipset_entry": F,
    "delete_firewall_ipset_entry": F,
    "add_node_firewall_rule": F,
    "delete_node_firewall_rule": F,
    "set_node_firewall_options": F,
    # ------------------------------------------------------------------ disks.py
    "list_node_disks": R,
    "get_disk_smart": R,
    "list_lvm_groups": R,
    "list_lvmthin_pools": R,
    "list_zfs_pools": R,
    "get_zfs_pool": R,
    "list_directory_storage": R,
    # Every host-disk mutation formats or wipes physical devices.
    "wipe_disk": F,
    "init_disk_gpt": F,
    "create_lvm_group": F,
    "delete_lvm_group": F,
    "create_lvmthin_pool": F,
    "delete_lvmthin_pool": F,
    "create_zfs_pool": F,
    "delete_zfs_pool": F,
    "create_directory_storage": F,
    "delete_directory_storage": F,
    # ------------------------------------------------------------------ ceph.py
    "get_ceph_status": R,
    "get_cluster_ceph_status": R,
    "get_ceph_crush": R,
    "get_ceph_log": R,
    "get_ceph_config": R,
    "get_ceph_config_db": R,
    "list_ceph_osds": R,
    "list_ceph_mons": R,
    "list_ceph_mgrs": R,
    "list_ceph_mds": R,
    "list_ceph_pools": R,
    "get_ceph_pool": R,
    "list_ceph_fs": R,
    "get_cluster_ceph_metadata": R,
    "get_cluster_ceph_flags": R,
    "set_ceph_osd_in": A,  # triggers rebalancing, reversible
    "set_ceph_osd_out": A,
    "create_ceph_mon": A,
    "create_ceph_mgr": A,
    "create_ceph_mds": A,
    "create_ceph_pool": A,
    "update_ceph_pool": A,
    "create_ceph_fs": A,
    "start_ceph": A,
    "restart_ceph": A,
    "set_cluster_ceph_flags": A,  # noout/pause etc.; maintenance flags, reversible
    # Destroying Ceph daemons, OSDs or pools loses data or quorum; OSD create formats a disk.
    "create_ceph_osd": F,
    "delete_ceph_osd": F,
    "delete_ceph_mon": F,
    "delete_ceph_mgr": F,
    "delete_ceph_mds": F,
    "delete_ceph_pool": F,
    "stop_ceph": F,  # storage outage for every guest on Ceph
    # ------------------------------------------------------------------ acme.py
    "get_node_certificates": R,
    "list_acme_directories": R,
    "get_acme_tos": R,
    "list_acme_challenge_schemas": R,
    # ACME accounts hold the account key; plugins hold DNS-provider API credentials in their
    # "data" field, which the GET responses return and field-name redaction cannot see.
    "list_acme_accounts": F,
    "get_acme_account": F,
    "register_acme_account": F,
    "deregister_acme_account": F,
    "list_acme_plugins": F,
    "get_acme_plugin": F,
    "create_acme_plugin": F,
    "update_acme_plugin": F,
    "delete_acme_plugin": F,
    # Node certificates are the trust anchor the broker pins; changing them breaks the pin
    # (lockout) or, with an uploaded key, enables interception.
    "order_node_acme_cert": F,
    "revoke_node_acme_cert": F,
    "upload_node_custom_cert": F,
    "delete_node_custom_cert": F,
    # ------------------------------------------------------------------ sdn.py
    "list_sdn_zones": R,
    "get_sdn_zone": R,
    "list_sdn_vnets": R,
    "get_sdn_vnet": R,
    "list_sdn_subnets": R,
    "list_node_sdn_zones": R,
    "list_node_sdn_vnets": R,
    # Guest networking objects. apply_sdn reloads networking on every node, so admin only.
    "apply_sdn": A,
    "create_sdn_zone": A,
    "update_sdn_zone": A,
    "delete_sdn_zone": A,
    "create_sdn_vnet": A,
    "update_sdn_vnet": A,
    "delete_sdn_vnet": A,
    "create_sdn_subnet": A,
    "delete_sdn_subnet": A,
    # ------------------------------------------------------------------ notifications.py
    "list_notification_targets": R,
    "list_gotify_endpoints": R,
    "get_gotify_endpoint": R,
    "list_sendmail_endpoints": R,
    "get_sendmail_endpoint": R,
    "list_smtp_endpoints": R,
    "list_webhook_endpoints": R,
    "list_notification_matchers": R,
    "get_notification_matcher": R,
    "list_notification_matcher_fields": R,
    # Endpoints carry secrets (gotify token, SMTP password, webhook secret) and decide where
    # alert data goes (an exfiltration channel); matchers decide which alerts fire (silencing).
    "create_gotify_endpoint": F,
    "update_gotify_endpoint": F,
    "delete_gotify_endpoint": F,
    "create_sendmail_endpoint": F,
    "update_sendmail_endpoint": F,
    "delete_sendmail_endpoint": F,
    "create_smtp_endpoint": F,
    "delete_smtp_endpoint": F,
    "create_webhook_endpoint": F,
    "delete_webhook_endpoint": F,
    "create_notification_matcher": F,
    "update_notification_matcher": F,
    "delete_notification_matcher": F,
    # ------------------------------------------------------------------ pools.py
    "list_pools": R,
    "get_pool": R,
    "create_pool": A,
    "update_pool": A,
    "delete_pool": A,
    # ------------------------------------------------------------------ appliances.py
    # Multi-step VM creation (create, resize, start). Creates guests: admin. The router refuses
    # deploy_fortigate_vm's image_url (it drives download-url, the SSRF path above); use an
    # import volume already on storage.
    "deploy_fortigate_vm": A,
    "deploy_cloud_vms": A,
}

# Safety net. A tool name matching any of these is forbidden even if the table is wrong.
# Keep these broad; a false positive only hides a tool, a false negative exposes one.
FORBIDDEN_PATTERNS: tuple[str, ...] = (
    r"passw(or)?d",
    r"(^|_)tfa(_|$)",
    r"totp",
    r"(^|_)tokens?(_|$)",  # API tokens (create/delete/regenerate and listing)
    r"(^|_)(create|update|delete|add|remove|set|change|modify)_(user|group|role|acl|auth_domain|realm)s?(_|$)",
    r"(^|_)sync_(auth_domain|realm)",
    r"agent_exec",
    r"agent_file",
    r"(^|_)exec(ute)?(_|$)",
    r"termproxy|vncshell|spiceshell|(^|_)(vnc|spice)(_|$)|(^|_)shell(_|$)",
    r"(^|_)ticket",
    r"(^|_)join",
    r"acme_account",
    r"acme_plugin",
    r"set_(cluster|node)_firewall_options",
    r"(add|update|delete)_(cluster|node)_firewall_rule",
    r"^delete_(\w+_)?storage",
    r"^create_storage$",
    r"(^|_)node_(shutdown|reboot|stopall)|(shutdown|reboot)_node(_|$)|stopall",
    r"(^|_)(dist_)?upgrade|apt_install",
    r"wipe",
    r"init_disk|initgpt",
    r"(^|_)destroy|(^|_)purge",
    r"delete_ceph_(osd|pool|mon)|create_ceph_osd",
    r"(upload|delete|revoke)_\w*cert",
    r"stop_node_service",
    r"apply_node_network|set_node_(dns|hosts)",
    r"metrics_server$",
    r"cloudinit",
    r"download_url",
    r"agent_(file|exec|set_user)",
    r"(^|_)(term|vnc|spice)_?proxy",
)
FORBIDDEN_RE = re.compile("|".join(f"(?:{p})" for p in FORBIDDEN_PATTERNS))


class PolicyDenied(Exception):
    """The caller is enrolled but may not run this tool. ``reason`` is safe to show."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def tool_tier(tool_name: str) -> Tier:
    if not isinstance(tool_name, str) or FORBIDDEN_RE.search(tool_name):
        return "forbidden"
    return TOOL_TIERS.get(tool_name, "forbidden")


def admin_enabled() -> bool:
    return os.environ.get("MCP_ALLOW_ADMIN_TOOLS", "").strip() == "1"


def allowed(mode: Mode, tier: Tier) -> bool:
    if tier == "read":
        return mode in ("ro", "operator", "rw")
    if tier == "operate":
        return mode in ("operator", "rw")
    if tier == "admin":
        return mode == "rw" and admin_enabled()
    return False


def _split_env(name: str) -> list[str]:
    return [p.strip() for p in os.environ.get(name, "").split(",") if p.strip()]


def operator_override_denies(tool_name: str) -> bool:
    """True when MCP_TOOL_DENY / MCP_TOOL_ALLOW exclude this tool. Read per call."""
    for pattern in _split_env("MCP_TOOL_DENY"):
        try:
            if re.search(pattern, tool_name):
                return True
        except re.error:
            # A broken deny list must not silently allow: deny everything until fixed.
            log.error("MCP_TOOL_DENY has an invalid regex %r; denying all tools", pattern)
            return True
    allow = _split_env("MCP_TOOL_ALLOW")
    return bool(allow) and tool_name not in allow


def permits(mode: Mode, tool_name: str) -> bool:
    """Whether a caller in this mode may run this tool (tier, flags and overrides)."""
    return allowed(mode, tool_tier(tool_name)) and not operator_override_denies(tool_name)


def _denial_reason(mode: Mode, tier: Tier) -> str:
    if tier == "operate":
        return "this MCP user is read-only"
    if tier == "admin":
        if mode != "rw":
            return "admin tools need a read-write MCP user"
        return "admin tools are disabled on this server (MCP_ALLOW_ADMIN_TOOLS)"
    return "not permitted for this MCP user"


def check_tool(identity: Identity, tool_name: str) -> Enrollment:
    """Authorize one tool call. Returns the caller's enrollment.

    Raises PermissionError("not enrolled") for unknown callers and PolicyDenied otherwise.
    """
    enrollment = enrollment_for(identity)
    tier = tool_tier(tool_name)
    if tier == "forbidden":
        raise PolicyDenied(f"{tool_name} is not available through MCP")
    if operator_override_denies(tool_name):
        raise PolicyDenied(f"{tool_name} is disabled by server policy")
    if not allowed(enrollment.mode, tier):
        raise PolicyDenied(f"{tool_name}: {_denial_reason(enrollment.mode, tier)}")
    return enrollment


def catalog_for(mode: Mode) -> list[dict[str, Any]]:
    """Tool definitions a caller in ``mode`` may run, with their tier, sorted by name.

    This is what the broker serves on /v1/catalog for the Worker's list/describe tools. It
    honours MCP_ALLOW_ADMIN_TOOLS, MCP_TOOL_DENY and MCP_TOOL_ALLOW (read per call).
    """
    from .router import REGISTRY  # late import: router imports this module

    out = []
    for name in sorted(REGISTRY):
        if permits(mode, name):
            tool_def = REGISTRY[name][0]
            out.append(
                {
                    "name": name,
                    "description": tool_def["description"],
                    "inputSchema": copy.deepcopy(tool_def["inputSchema"]),
                    "tier": tool_tier(name),
                }
            )
    return out


def catalog_version(mode: Mode | None = None) -> str:
    """sha256 hex of the canonical catalog JSON, for cache busting.

    With a mode: the version of that mode's catalog. Without: of all three modes together,
    so any change to tools, tiers, flags or overrides changes it.
    """
    modes: tuple[Mode, ...] = (mode,) if mode else ("ro", "operator", "rw")
    doc = {m: catalog_for(m) for m in modes}
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()
