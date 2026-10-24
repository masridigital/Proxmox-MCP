"""Outbound method/path policy."""

import asyncio
import re

import pytest

from proxmox_mcp import outbound, router


@pytest.mark.parametrize(
    "path",
    [
        "nodes",
        "/nodes/../access/users",
        "/nodes/./x",
        "/nodes//pve",
        "/nodes/pve?x=1",
        "/nodes/pve#frag",
        "/nodes/pve%2e%2e",
        "/nodes/%2E%2E%2Faccess",
        "/nodes/pve%00",
        "/nodes/p ve",
        "/nodes/pve\\qemu",
        "/nodes/pve\n",
        "/nodes/pve\x7f",
        "/nodes/pvé",
        "/nodes/",
        "/nodes/pve/storage/local/content/a%2F..%2Fb",
        "/nodes/pve/storage/local/content/%2F",
        "/x" * 2000,
    ],
)
def test_invalid_paths_rejected(path):
    with pytest.raises(PermissionError, match="blocked by outbound policy"):
        outbound.check("GET", path, "rw")


@pytest.mark.parametrize(
    "value", ["", ".", "..", "a/b", "a..b", "a?b", "a%2F", "x" * 129, "a b", True, None, 1.5, "ü"]
)
def test_safe_segment_rejects(value):
    with pytest.raises(ValueError):
        outbound.safe_segment(value)


@pytest.mark.parametrize("value", ["pve01", "local-lvm", "vm:100", "a.b_c", 100])
def test_safe_segment_accepts(value):
    assert outbound.safe_segment(value) == str(value)


def test_ro_is_get_only():
    outbound.check("GET", "/nodes/pve/qemu/100/config", "ro")
    for method in ("POST", "PUT", "DELETE"):
        with pytest.raises(PermissionError):
            outbound.check(method, "/nodes/pve/qemu/100/status/start", "ro")


def test_operator_writes_are_limited():
    outbound.check("POST", "/nodes/pve/qemu/100/status/start", "operator")
    outbound.check("POST", "/nodes/pve/lxc/100/snapshot", "operator")
    with pytest.raises(PermissionError, match="requires rw"):
        outbound.check("PUT", "/nodes/pve/qemu/100/config", "operator")
    with pytest.raises(PermissionError, match="DELETE requires rw"):
        outbound.check("DELETE", "/nodes/pve/qemu/100", "operator")


def test_rw_delete_and_typed_placeholders():
    outbound.check("DELETE", "/nodes/pve/qemu/100", "rw")
    with pytest.raises(PermissionError, match="allowlist"):
        outbound.check("DELETE", "/nodes/pve/qemu/abc", "rw")  # vmid must be digits
    outbound.check("GET", "/nodes/pve/tasks/UPID:pve:0000ABCD:0123ABCD:65A1B2C3:qmstart:100:root@pam:/status", "ro")
    outbound.check("GET", "/nodes/pve/storage/local/content/local%3Aiso%2Fubuntu.iso", "ro")
    outbound.check("DELETE", "/cluster/firewall/ipset/blk/10.0.0.0%2F24", "rw")


def test_unknown_mode_and_method():
    with pytest.raises(PermissionError):
        outbound.check("GET", "/nodes", "admin")
    with pytest.raises(PermissionError):
        outbound.check("PATCH", "/nodes", "rw")


def test_not_in_allowlist():
    with pytest.raises(PermissionError, match="allowlist"):
        outbound.check("GET", "/nodes/pve/qemu/100/unknown", "rw")


@pytest.mark.parametrize(
    "method, path",
    [
        ("POST", "/access/users"),
        ("PUT", "/access/acl"),
        ("GET", "/access/users/root@pam/token"),
        ("GET", "/access/users/root@pam/token/mcp"),
        ("PUT", "/access/password"),
        ("GET", "/access/tfa"),
        ("GET", "/access/tfa/root@pam"),
        ("POST", "/access/ticket"),
        ("POST", "/nodes/pve/termproxy"),
        ("GET", "/nodes/pve/vncshell"),
        ("POST", "/nodes/pve/spiceshell"),
        ("POST", "/nodes/pve/qemu/100/vncproxy"),
        ("POST", "/nodes/pve/qemu/100/spiceproxy"),
        ("POST", "/nodes/pve/lxc/100/termproxy"),
        ("POST", "/nodes/pve/qemu/100/agent/exec"),
        ("GET", "/nodes/pve/qemu/100/agent/exec-status"),
        ("POST", "/nodes/pve/qemu/100/agent/file-write"),
        ("GET", "/nodes/pve/qemu/100/agent/file-read"),
        ("POST", "/nodes/pve/qemu/100/agent/set-user-password"),
        ("POST", "/nodes/pve/execute"),
        ("POST", "/cluster/config/join"),
        ("POST", "/nodes/pve/apt/update"),
        ("POST", "/nodes/pve/status"),
        ("POST", "/nodes/pve/stopall"),
        ("GET", "/cluster/acme/account"),
        ("POST", "/cluster/acme/account"),
        ("DELETE", "/cluster/acme/account/default"),
        ("POST", "/nodes/pve/certificates/custom"),
    ],
)
def test_global_deny_applies_to_rw(method, path):
    with pytest.raises(PermissionError, match="blocked by outbound policy"):
        outbound.check(method, path, "rw")
    assert outbound.deny_reason(method, path)


def test_reads_still_allowed_in_sensitive_areas():
    outbound.check("GET", "/access/users", "ro")
    outbound.check("GET", "/nodes/pve/apt/update", "ro")
    outbound.check("GET", "/nodes/pve/status", "ro")


class _Recorder:
    def __init__(self):
        self.calls = []

    async def request(self, method, path, data=None):
        self.calls.append((method, path))
        if path == "/cluster/nextid":
            return {"data": "7777"}
        if "/tasks/" in path:
            return {"data": {"status": "stopped", "exitstatus": "OK"}}
        return {"data": []}

    async def get(self, p, d=None):
        return await self.request("GET", p, d)

    async def post(self, p, d=None):
        return await self.request("POST", p, d)

    async def put(self, p, d=None):
        return await self.request("PUT", p, d)

    async def delete(self, p, d=None):
        return await self.request("DELETE", p, d)


def _value(name, spec, i):
    if "enum" in spec:
        return spec["enum"][0]
    t = spec.get("type")
    if t in ("integer", "number"):
        return 100 + i
    if t == "boolean":
        return True
    if t == "array":
        return ["x"]
    if t == "object":
        return {}
    if name == "userid":
        return "dev@pve"
    if name == "upid":
        return "UPID:pve:0000ABCD:0123ABCD:65A1B2C3:qmstart:100:root@pam:"
    return "v" + re.sub(r"[^a-z0-9]", "", name)


async def test_every_tool_path_is_allowlisted_or_denied():
    """Run each handler against a recorder: every path it builds must be known to the policy."""
    unknown = []
    for name, (tool_def, module) in router.REGISTRY.items():
        props = tool_def["inputSchema"].get("properties", {})
        for args in (
            {k: _value(k, v, i) for i, (k, v) in enumerate(props.items())},
            {k: _value(k, v, i) for i, (k, v) in enumerate(props.items())
             if k in tool_def["inputSchema"].get("required", [])},
        ):
            rec = _Recorder()
            try:
                await asyncio.wait_for(module.handle(name, args, rec), 2)
            except Exception:
                pass
            for method, path in rec.calls:
                try:
                    outbound.check(method, path, "rw")
                except PermissionError as exc:
                    if "allowlist" in str(exc) or "invalid path" in str(exc):
                        unknown.append((name, method, path))
    assert unknown == []


def test_operator_writes_match_operate_tier():
    """Inbound operate tier and outbound operator writes must name the same endpoints."""
    from proxmox_mcp import outbound, policy

    operate = {t for t, tier in policy.TOOL_TIERS.items() if tier == "operate"}
    templates = {tpl for tpl, _ in outbound.OPERATOR_WRITES}
    assert len(templates) == 16  # 6 power actions x qemu/lxc, reset, 2 snapshots, agent ping
    assert len(operate) == 16  # 12 power + reset + 2 snapshots + agent ping
