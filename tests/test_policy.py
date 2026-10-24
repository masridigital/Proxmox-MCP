"""Tool tiers, mode checks, operator overrides, catalog and enrollment validation."""

from __future__ import annotations

import asyncio
import json
import re

import pytest

from proxmox_mcp import enrollment, policy, router
from proxmox_mcp.identity import Identity

ALL = sorted(router.REGISTRY)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "MCP_ALLOW_ADMIN_TOOLS",
        "MCP_TOOL_DENY",
        "MCP_TOOL_ALLOW",
        "MCP_LOCAL_MODE",
        "MCP_ENROLLMENT_FILE",
        "CREDENTIALS_DIRECTORY",
        "BROKER_CREDENTIALS_DIR",
    ):
        monkeypatch.delenv(var, raising=False)


def _write(tmp_path, doc, name="enrollment.json"):
    path = tmp_path / name
    path.write_text(json.dumps(doc) if not isinstance(doc, str) else doc, encoding="utf-8")
    return str(path)


def _entry(mode="ro", userid="alice@pve", cred="pve-token-alice"):
    return {"mode": mode, "proxmox_userid": userid, "token_credential": cred}


# ----------------------------------------------------------------------------- classification


def test_every_registered_tool_has_an_explicit_entry():
    missing = [n for n in ALL if n not in policy.TOOL_TIERS]
    assert missing == []


def test_table_has_no_stale_entries():
    assert sorted(set(policy.TOOL_TIERS) - set(router.REGISTRY)) == []


def test_regex_safety_net_agrees_with_table():
    disagree = [
        n for n in ALL if policy.FORBIDDEN_RE.search(n) and policy.TOOL_TIERS[n] != "forbidden"
    ]
    assert disagree == []


def test_unknown_tool_is_forbidden():
    assert policy.tool_tier("no_such_tool") == "forbidden"
    assert policy.tool_tier("") == "forbidden"


def test_regex_overrides_a_wrong_table(monkeypatch):
    monkeypatch.setitem(policy.TOOL_TIERS, "vm_agent_exec", "read")
    monkeypatch.setitem(policy.TOOL_TIERS, "create_user_token", "operate")
    assert policy.tool_tier("vm_agent_exec") == "forbidden"
    assert policy.tool_tier("create_user_token") == "forbidden"


DANGEROUS = [
    "change_user_password",
    "vm_agent_set_user_password",
    "vm_agent_exec",
    "vm_agent_exec_status",
    "add_tfa",
    "delete_tfa",
    "list_tfa",
    "create_user_token",
    "delete_user_token",
    "update_user_token",
    "create_user",
    "delete_user",
    "update_acl",
    "create_role",
    "update_role",
    "delete_role",
    "create_group",
    "delete_group",
    "create_auth_domain",
    "delete_auth_domain",
    "sync_auth_domain",
    "get_vm_vnc_proxy",
    "get_vm_spice_proxy",
    "register_acme_account",
    "deregister_acme_account",
    "get_acme_plugin",
    "set_cluster_firewall_options",
    "set_node_firewall_options",
    "delete_storage",
    "delete_storage_volume",
    "create_storage",
    "node_shutdown",
    "node_stopall",
    "wipe_disk",
    "init_disk_gpt",
    "delete_ceph_osd",
    "delete_ceph_pool",
    "upload_node_custom_cert",
    "stop_node_service",
    "apply_node_network",
    "create_webhook_endpoint",
]


@pytest.mark.parametrize("name", DANGEROUS)
def test_dangerous_tools_are_forbidden(name):
    assert name in router.REGISTRY
    assert policy.tool_tier(name) == "forbidden"


@pytest.mark.parametrize(
    "name",
    [
        "create_cluster_join",
        "termproxy_node",
        "node_vncshell",
        "get_ticket",
        "apt_upgrade_node",
        "set_vm_password",
        "regenerate_user_token",
        "ceph_purge",
        "node_reboot",
        "execute_cmd",
    ],
)
def test_hypothetical_dangerous_names_hit_the_regex(name):
    assert policy.FORBIDDEN_RE.search(name)


def test_destructive_vm_ops_are_admin():
    for name in (
        "delete_vm",
        "rollback_vm_snapshot",
        "delete_container",
        "clone_vm",
        "set_vm_config",
        "resize_vm_disk",
        "migrate_vm",
        "add_vm_firewall_rule",
        "update_pool",
    ):
        assert policy.tool_tier(name) == "admin", name


def test_lifecycle_ops_are_operate():
    for name in (
        "start_vm",
        "stop_vm",
        "shutdown_vm",
        "reboot_vm",
        "suspend_vm",
        "resume_vm",
        "create_vm_snapshot",
        "start_container",
        "shutdown_container",
    ):
        assert policy.tool_tier(name) == "operate", name


# Trace every handler with a fake client and check tiers against the HTTP methods it sends.


class _Recorder:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    async def request(self, method, path, data=None):
        self.calls.append((method, path))
        return {"data": "100"}

    async def get(self, path, params=None):
        return await self.request("GET", path, params)

    async def post(self, path, data=None):
        return await self.request("POST", path, data)

    async def put(self, path, data=None):
        return await self.request("PUT", path, data)

    async def delete(self, path, params=None):
        return await self.request("DELETE", path, params)


def _dummy(schema):
    return {"integer": 100, "number": 1, "boolean": True, "array": ["a"], "object": {}}.get(
        schema.get("type"), "x1"
    )


def _trace() -> dict[str, set[str]]:
    methods: dict[str, set[str]] = {}

    async def run():
        for name, (tool_def, mod) in router.REGISTRY.items():
            schema = tool_def["inputSchema"]
            args = {k: _dummy(schema["properties"].get(k, {})) for k in schema.get("required", [])}
            rec = _Recorder()
            try:
                await mod.handle(name, args, rec)
            except Exception:  # dummy args may not satisfy a handler; the calls so far count
                pass
            methods[name] = {m for m, _ in rec.calls}

    asyncio.run(run())
    return methods


TRACE = _trace()


def test_non_get_tools_are_never_read():
    bad = [n for n, ms in TRACE.items() if ms - {"GET"} and policy.tool_tier(n) == "read"]
    assert bad == []


def test_delete_tools_are_admin_or_forbidden():
    bad = [
        n
        for n, ms in TRACE.items()
        if "DELETE" in ms and policy.tool_tier(n) in ("read", "operate")
    ]
    assert bad == []


def test_every_tool_reached_the_api():
    # Guards the trace itself: a handler that sent nothing would make the checks above vacuous.
    silent = [n for n, ms in TRACE.items() if not ms and n != "deploy_fortigate_vm"]
    assert silent == []


# ----------------------------------------------------------------------------- modes


def test_allowed_matrix(monkeypatch):
    assert policy.allowed("ro", "read")
    assert not policy.allowed("ro", "operate")
    assert not policy.allowed("ro", "admin")
    assert policy.allowed("operator", "operate")
    assert not policy.allowed("operator", "admin")
    assert policy.allowed("rw", "operate")
    assert not policy.allowed("rw", "admin")
    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "1")
    assert policy.allowed("rw", "admin")
    assert not policy.allowed("operator", "admin")
    for mode in ("ro", "operator", "rw"):
        assert not policy.allowed(mode, "forbidden")


def _local(monkeypatch, mode):
    monkeypatch.setenv("MCP_LOCAL_MODE", mode)
    return Identity(subject="local", kind="local")


def test_check_tool_ro(monkeypatch):
    ident = _local(monkeypatch, "ro")
    assert policy.check_tool(ident, "list_vms").mode == "ro"
    with pytest.raises(policy.PolicyDenied, match="read-only"):
        policy.check_tool(ident, "start_vm")
    with pytest.raises(policy.PolicyDenied):
        policy.check_tool(ident, "delete_vm")


def test_check_tool_forbidden_for_everyone(monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "1")
    ident = _local(monkeypatch, "rw")
    with pytest.raises(policy.PolicyDenied, match="not available through MCP"):
        policy.check_tool(ident, "vm_agent_exec")
    with pytest.raises(policy.PolicyDenied):
        policy.check_tool(ident, "nonexistent_tool")


def test_admin_needs_rw_and_flag(monkeypatch):
    ident = _local(monkeypatch, "rw")
    with pytest.raises(policy.PolicyDenied, match="MCP_ALLOW_ADMIN_TOOLS"):
        policy.check_tool(ident, "delete_vm")
    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "1")
    assert policy.check_tool(ident, "delete_vm").mode == "rw"
    op = _local(monkeypatch, "operator")
    with pytest.raises(policy.PolicyDenied, match="read-write"):
        policy.check_tool(op, "delete_vm")
    assert policy.check_tool(op, "start_vm").mode == "operator"


def test_flag_must_be_exactly_1(monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "true")
    assert not policy.allowed("rw", "admin")


def test_unenrolled_user_is_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", str(tmp_path / "missing.json"))
    with pytest.raises(PermissionError, match="not enrolled"):
        policy.check_tool(Identity(subject="x", kind="user", email="x@example.com"), "list_vms")


def test_deny_override(monkeypatch):
    ident = _local(monkeypatch, "operator")
    monkeypatch.setenv("MCP_TOOL_DENY", r"^stop_, snapshot")
    with pytest.raises(policy.PolicyDenied, match="server policy"):
        policy.check_tool(ident, "stop_vm")
    with pytest.raises(policy.PolicyDenied):
        policy.check_tool(ident, "list_vm_snapshots")
    assert policy.check_tool(ident, "start_vm")


def test_invalid_deny_regex_denies_everything(monkeypatch):
    monkeypatch.setenv("MCP_TOOL_DENY", "([")
    assert not policy.permits("rw", "list_vms")


def test_allow_override_only_restricts(monkeypatch):
    ident = _local(monkeypatch, "ro")
    monkeypatch.setenv("MCP_TOOL_ALLOW", "list_vms, start_vm, vm_agent_exec")
    assert policy.check_tool(ident, "list_vms")
    with pytest.raises(policy.PolicyDenied):
        policy.check_tool(ident, "list_nodes")  # not in the allow list
    with pytest.raises(policy.PolicyDenied):
        policy.check_tool(ident, "start_vm")  # allow list cannot raise ro to operate
    with pytest.raises(policy.PolicyDenied):
        policy.check_tool(ident, "vm_agent_exec")  # nor un-forbid


# ----------------------------------------------------------------------------- catalog


def test_catalog_for_modes(monkeypatch):
    ro = policy.catalog_for("ro")
    assert ro == sorted(ro, key=lambda d: d["name"])
    assert {d["tier"] for d in ro} == {"read"}
    assert set(ro[0]) == {"name", "description", "inputSchema", "tier", "category"}
    op = {d["tier"] for d in policy.catalog_for("operator")}
    assert op == {"read", "operate"}
    assert "admin" not in {d["tier"] for d in policy.catalog_for("rw")}
    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "1")
    rw = policy.catalog_for("rw")
    assert {d["tier"] for d in rw} == {"read", "operate", "admin"}
    assert not any(d["tier"] == "forbidden" for d in rw)


def test_catalog_respects_overrides_and_version(monkeypatch):
    before = policy.catalog_version()
    assert re.fullmatch(r"[0-9a-f]{64}", before)
    assert policy.catalog_version() == before
    monkeypatch.setenv("MCP_TOOL_DENY", "^list_vms$")
    assert "list_vms" not in {d["name"] for d in policy.catalog_for("ro")}
    assert policy.catalog_version() != before


def test_catalog_entries_are_copies():
    entry = policy.catalog_for("ro")[0]
    entry["inputSchema"]["properties"]["injected"] = {}
    assert "injected" not in router.REGISTRY[entry["name"]][0]["inputSchema"]["properties"]


# ----------------------------------------------------------------------------- enrollment


def test_enrollment_valid_and_lowercased(tmp_path):
    path = _write(
        tmp_path,
        {
            "users": {"Alice@Example.COM": _entry("rw")},
            "services": {"abc123.access": _entry("ro", "svc@pve", "pve-token-svc")},
        },
    )
    table = enrollment.load_enrollments(path)
    assert table["alice@example.com"].mode == "rw"
    assert table["alice@example.com"].subject == "alice@example.com"
    assert table["service:abc123.access"].proxmox_userid == "svc@pve"


def test_enrollment_for_user_and_service(tmp_path, monkeypatch):
    path = _write(
        tmp_path,
        {
            "users": {"alice@example.com": _entry("operator")},
            "services": {"abc123.access": _entry("ro", "svc@pve", "pve-token-svc")},
        },
    )
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", path)
    user = Identity(subject="ignored", kind="user", email="ALICE@example.com")
    assert enrollment.enrollment_for(user).mode == "operator"
    svc = Identity(subject="abc123.access", kind="service")
    assert enrollment.enrollment_for(svc).proxmox_userid == "svc@pve"
    # A service subject never matches a user entry and vice versa.
    with pytest.raises(PermissionError):
        enrollment.enrollment_for(Identity(subject="alice@example.com", kind="service"))
    with pytest.raises(PermissionError):
        enrollment.enrollment_for(Identity(subject="abc123.access", kind="user"))
    with pytest.raises(PermissionError):
        enrollment.enrollment_for(Identity(subject="bob", kind="user", email="bob@example.com"))
    with pytest.raises(PermissionError):
        enrollment.enrollment_for(Identity(subject="x", kind="weird"))


@pytest.mark.parametrize(
    "doc",
    [
        {"users": {"alice@example.com": _entry(userid="root@pam")}},
        {"users": {"alice@example.com": _entry(userid="ROOT@pam")}},
        {"users": {"not-an-email": _entry()}},
        {"users": {"alice@example": _entry()}},
        {"users": {"alice@example.com": {**_entry(), "extra": 1}}},
        {"users": {"alice@example.com": {"mode": "ro", "proxmox_userid": "a@pve"}}},
        {"users": {"alice@example.com": _entry(mode="admin")}},
        {"users": {"alice@example.com": _entry(userid="alice")}},
        {"users": {"alice@example.com": _entry(userid="alice@pve!tok")}},
        {"users": {"alice@example.com": _entry(cred="../etc/passwd")}},
        {"users": {"alice@example.com": _entry(cred="..")}},
        {"users": {"alice@example.com": _entry(cred="x" * 65)}},
        {"users": {"alice@example.com": _entry(), "ALICE@example.com": _entry()}},
        {"users": {}, "extra": {}},
        {"services": {}},
        {"users": []},
        {"users": {}, "services": {"bad subject!": _entry()}},
        [],
    ],
)
def test_enrollment_rejects_invalid(tmp_path, doc):
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.load_enrollments(_write(tmp_path, doc))


def test_enrollment_rejects_duplicate_json_keys(tmp_path):
    first, second = json.dumps(_entry()), json.dumps(_entry("rw"))
    text = f'{{"users": {{"a@example.com": {first}, "a@example.com": {second}}}}}'
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.load_enrollments(_write(tmp_path, text))


def test_enrollment_missing_file_is_empty(tmp_path):
    assert enrollment.load_enrollments(str(tmp_path / "nope.json")) == {}
    assert enrollment.load_enrollments() == {}  # nothing configured


def test_invalid_file_denies_everyone(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", _write(tmp_path, "{not json"))
    with pytest.raises(PermissionError, match="not enrolled"):
        enrollment.enrollment_for(Identity(subject="a", kind="user", email="a@example.com"))


def test_enrollment_reloads_on_change(tmp_path):
    path = _write(tmp_path, {"users": {"a@example.com": _entry("ro")}})
    assert enrollment.load_enrollments(path)["a@example.com"].mode == "ro"
    _write(
        tmp_path,
        {
            "users": {
                "a@example.com": _entry("rw"),
                "b@example.com": _entry("ro", "bob@pve", "pve-token-bob"),
            }
        },
    )
    assert enrollment.load_enrollments(path)["a@example.com"].mode == "rw"


def test_default_path_from_credentials_dirs(tmp_path, monkeypatch):
    monkeypatch.setenv("BROKER_CREDENTIALS_DIR", str(tmp_path))
    _write(tmp_path, {"users": {"a@example.com": _entry()}})
    assert "a@example.com" in enrollment.load_enrollments()


def test_local_identity_defaults_to_ro(monkeypatch):
    ident = Identity(subject="local", kind="local")
    assert enrollment.enrollment_for(ident).mode == "ro"
    assert enrollment.enrollment_for(ident).token_credential == ""
    monkeypatch.setenv("MCP_LOCAL_MODE", "rw")
    assert enrollment.enrollment_for(ident).mode == "rw"
    monkeypatch.setenv("MCP_LOCAL_MODE", "superuser")
    assert enrollment.enrollment_for(ident).mode == "ro"


# ----------------------------------------------------------------------------- compliance

GUEST_CONTENT_FORBIDDEN = {
    "vm_agent_exec",  # code execution in the guest
    "vm_agent_exec_status",  # guest command output
    "vm_agent_set_user_password",  # guest OS user/password
    "get_vm_vnc_proxy",  # console
    "get_vm_spice_proxy",  # console
    "get_vm_cloudinit",  # cloud-init user-data (secrets)
    "regenerate_vm_cloudinit",  # writes the cloud-init drive
    "download_url_to_storage",  # URL -> storage (SSRF, guest boot media)
}


def test_guest_content_tools_are_forbidden():
    forbidden = {n for n in ALL if policy.tool_tier(n) == "forbidden"}
    assert GUEST_CONTENT_FORBIDDEN <= forbidden
    # Any future guest-agent tool other than the three metadata reads must be forbidden too.
    agent = {n for n in ALL if "agent" in n} - {
        "vm_agent_get_fsinfo",
        "vm_agent_get_network_interfaces",
        "vm_agent_get_osinfo",
        "vm_agent_ping",
    }
    assert agent <= forbidden
    for name in (
        "vm_agent_file_read",
        "vm_agent_file_write",
        "node_termproxy",
        "get_vm_cloudinit_dump",
        "download_url_to_iso",
    ):
        assert policy.tool_tier(name) == "forbidden"


def test_guest_content_never_in_any_catalog(monkeypatch):
    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "1")
    names = {d["name"] for d in policy.catalog_for("rw")}
    assert not names & GUEST_CONTENT_FORBIDDEN
