"""Minimal valid arguments for every registered tool, derived from its inputSchema.

Only the schema's required properties are filled. Values come from a per-tool
override (TOOL_OVERRIDES) where the same name means a different thing in a
different tool, then the property name (KEY_VALUES), then the first enum value,
then the JSON type. All values are documentation placeholders: example.com and
192.0.2.0/24 (TEST-NET-1).
"""

from __future__ import annotations

from typing import Any

UPID = "UPID:pve1:0000ABCD:00000001:65000000:qmstart:100:mcp-rw@pve!mcp:"

KEY_VALUES: dict[str, Any] = {
    "node": "pve1",
    "vmid": 100,
    "newid": 101,
    "storage": "local",
    "poolid": "pool1",
    "snapname": "snap1",
    "iface": "vmbr0",
    "service": "pveproxy",
    "upid": UPID,
    "sid": "vm:100",
    "userid": "jdoe@pve",
    "tokenid": "tok1",
    "groupid": "grp1",
    "roleid": "Role1",
    "realm": "corp",
    "zone": "zone1",
    "vnet": "vnet1",
    "monid": "pve1",
    "group": "grp1",
    "id": "job1",
    "name": "name1",
    "type": "dir",
    "volume": "local:iso/test.iso",
    "cidr": "192.0.2.0/24",
    "subnet": "zone1-192.0.2.0-24",
    "osdid": 0,
    "pos": 0,
    "pid": 1,
    "port": 8086,
    "action": "ACCEPT",
    "archive": "local:backup/vzdump-qemu-100.vma.zst",
    "certificates": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
    "command": "ls",
    "contact": "ops@example.com",
    "content": "iso",
    "data": "127.0.0.1 localhost",
    "dev": "/dev/sdb",
    "device": "/dev/sdb",
    "devices": "/dev/sdb",
    "disk": "scsi0",
    "ds": "cpu",
    "feature": "snapshot",
    "filename": "test.iso",
    "from-address": "pve@example.com",
    "idlist": "scsi1",
    "image": "local:import/test.qcow2",
    "method": "POST",
    "names": ["vm1"],
    "ostemplate": "local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst",
    "password": "not-a-real-password",
    "path": "/mnt/data",
    "raidlevel": "single",
    "roles": "PVEAuditor",
    "schedule": "daily",
    "server": "192.0.2.10",
    "size": "+1G",
    "source": "local:import/disk.qcow2",
    "ssh_public_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample user@example.com",
    "target": "pve2",
    "timeframe": "hour",
    "timezone": "UTC",
    "token": "not-a-real-token",
    "url": "https://example.com/test.iso",
    "username": "jdoe",
    "volume-group": "vg1",
}

TOOL_OVERRIDES: dict[str, dict[str, Any]] = {
    "get_disk_smart": {"disk": "/dev/sda"},
    "wipe_disk": {"disk": "/dev/sdb"},
    "init_disk_gpt": {"disk": "/dev/sdb"},
    "resize_container_disk": {"disk": "rootfs"},
    "move_container_disk": {"disk": "rootfs"},
    "add_vm_firewall_rule": {"type": "in"},
    "add_container_firewall_rule": {"type": "in"},
    "add_cluster_firewall_rule": {"type": "in"},
    "add_firewall_group_rule": {"type": "in"},
    "add_node_firewall_rule": {"type": "in"},
    "get_node_scan": {"type": "nfs"},
    "get_vm_cloudinit": {"type": "user"},
    "create_replication_job": {"id": "100-0", "type": "local"},
    "get_replication_job": {"id": "100-0"},
    "update_replication_job": {"id": "100-0"},
    "delete_replication_job": {"id": "100-0"},
    "create_metrics_server": {"type": "influxdb"},
    "update_acl": {"path": "/vms/100"},
    "create_auth_domain": {"type": "ldap"},
    "add_tfa": {"type": "totp"},
    "create_acme_plugin": {"type": "dns"},
    "create_sdn_zone": {"type": "simple"},
    "create_sdn_subnet": {"type": "subnet"},
    "node_shutdown": {"command": "shutdown"},
    "copy_storage_volume": {"target": "local:iso/copy.iso"},
    "create_gotify_endpoint": {"server": "https://gotify.example.com"},
    "create_smtp_endpoint": {"server": "smtp.example.com"},
    "get_node_apt_changelog": {"name": "pve-manager"},
}

# Optional properties that a tool needs anyway (the schema cannot say "one of").
TOOL_EXTRAS: dict[str, dict[str, Any]] = {
    "deploy_fortigate_vm": {"image": "local:import/fortios.qcow2"},
}

_TYPE_DEFAULTS: dict[str, Any] = {
    "string": "x1",
    "integer": 1,
    "number": 1,
    "boolean": True,
    "array": [],
    "object": {},
}


def _value(tool: str, key: str, prop: dict[str, Any]) -> Any:
    if key in TOOL_OVERRIDES.get(tool, {}):
        return TOOL_OVERRIDES[tool][key]
    if key in KEY_VALUES:
        return KEY_VALUES[key]
    if prop.get("enum"):
        return prop["enum"][0]
    return _TYPE_DEFAULTS[prop.get("type", "string")]


def minimal_args(tool: str, tool_def: dict[str, Any]) -> dict[str, Any]:
    """Arguments with every required property of ``tool_def`` (plus TOOL_EXTRAS)."""
    schema = tool_def["inputSchema"]
    props = schema.get("properties", {})
    args = {key: _value(tool, key, props.get(key, {})) for key in schema.get("required", [])}
    args.update(TOOL_EXTRAS.get(tool, {}))
    return args
