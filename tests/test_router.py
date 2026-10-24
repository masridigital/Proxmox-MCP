"""STD-02 meta-tools: registry, filtering, describe, execute and schema validation."""

from __future__ import annotations

import json

import pytest

from proxmox_mcp import router
from proxmox_mcp.identity import Identity, current_identity
from proxmox_mcp.router import RouterError, handle_meta, validate_arguments


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in (
        "MCP_ALLOW_ADMIN_TOOLS",
        "MCP_TOOL_DENY",
        "MCP_TOOL_ALLOW",
        "MCP_ENROLLMENT_FILE",
        "CREDENTIALS_DIRECTORY",
        "BROKER_CREDENTIALS_DIR",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("MCP_LOCAL_MODE", "ro")


@pytest.fixture
def as_local():
    token = current_identity.set(Identity(subject="local", kind="local"))
    yield
    current_identity.reset(token)


class _Exec:
    def __init__(self):
        self.calls = []

    async def __call__(self, tool, arguments):
        self.calls.append((tool, arguments))
        return "ok"


# ----------------------------------------------------------------------------- registry


def test_registry_complete_and_unique():
    total = sum(len(m.TOOLS) for m in router.MODULES)
    assert len(router.REGISTRY) == total
    assert not set(router.META_TOOL_NAMES) & set(router.REGISTRY)


def test_duplicate_names_raise():
    class Mod:
        __name__ = "fake"
        TOOLS = [{"name": "a"}, {"name": "a"}]

    with pytest.raises(RuntimeError, match="duplicate"):
        router._build_registry([Mod])


def test_meta_tools_annotations():
    tools = {t.name: t for t in router.meta_tools()}
    assert set(tools) == {"list_tools", "describe_tool_input", "execute_tool"}
    for name in ("list_tools", "describe_tool_input"):
        assert tools[name].annotations.readOnlyHint and tools[name].annotations.idempotentHint
    ex = tools["execute_tool"].annotations
    assert ex.destructiveHint and ex.openWorldHint and not ex.readOnlyHint
    st = tools["list_tools"].inputSchema["properties"]["search_terms"]
    assert st["maxItems"] == 5 and st["items"]["maxLength"] == 64
    assert tools["describe_tool_input"].inputSchema["properties"]["tool_names"]["maxItems"] == 10


# ----------------------------------------------------------------------------- list_tools


async def test_list_tools_filters_by_mode(as_local, monkeypatch):
    names = {
        d["name"]
        for d in json.loads(await handle_meta("list_tools", {"search_terms": ["vm"]}, _Exec()))
    }
    assert "list_vms" in names
    assert "start_vm" not in names and "delete_vm" not in names and "vm_agent_exec" not in names

    monkeypatch.setenv("MCP_LOCAL_MODE", "rw")
    names = {
        d["name"]
        for d in json.loads(await handle_meta("list_tools", {"search_terms": ["_vm"]}, _Exec()))
    }
    assert "start_vm" in names and "delete_vm" not in names

    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "1")
    out = json.loads(
        await handle_meta("list_tools", {"search_terms": ["delete_vm", "agent"]}, _Exec())
    )
    names = {d["name"] for d in out}
    assert "delete_vm" in names
    assert not {"vm_agent_exec", "vm_agent_set_user_password", "vm_agent_exec_status"} & names


async def test_list_tools_case_insensitive_or(as_local):
    out = json.loads(await handle_meta("list_tools", {"search_terms": ["CEPH", "ZFS"]}, _Exec()))
    names = {d["name"] for d in out}
    assert "get_ceph_status" in names and "list_zfs_pools" in names
    assert all(set(d) == {"name", "description"} for d in out)


async def test_list_tools_cap(as_local):
    out = json.loads(await handle_meta("list_tools", {"search_terms": ["get", "list"]}, _Exec()))
    assert "Narrow your terms" in out["note"]
    assert len(out["tools"]) == router.LIST_CAP


async def test_list_tools_without_terms_is_a_summary(as_local):
    text = await handle_meta("list_tools", {}, _Exec())
    out = json.loads(text)
    assert "categories" in out and out["visible_tools"] > 0
    assert len(text) < 8000
    assert "start_vm" not in text


async def test_list_tools_unenrolled_sees_nothing(tmp_path):
    token = current_identity.set(Identity(subject="x", kind="user", email="x@example.com"))
    try:
        assert json.loads(await handle_meta("list_tools", {"search_terms": ["vm"]}, _Exec())) == []
    finally:
        current_identity.reset(token)


async def test_list_tools_rejects_bad_terms(as_local):
    with pytest.raises(RouterError, match="Invalid input for tool list_tools"):
        await handle_meta("list_tools", {"search_terms": ["a"] * 6}, _Exec())
    with pytest.raises(RouterError):
        await handle_meta("list_tools", {"search_terms": ["x" * 65]}, _Exec())
    with pytest.raises(RouterError):
        await handle_meta("list_tools", {"query": "vm"}, _Exec())


async def test_no_identity_fails_closed():
    with pytest.raises(PermissionError):
        await handle_meta("list_tools", {}, _Exec())


# ----------------------------------------------------------------------------- describe


async def test_describe_visible(as_local):
    out = await handle_meta(
        "describe_tool_input", {"tool_names": ["list_vms", "get_vm_config"]}, _Exec()
    )
    assert out.count("<input_schema tool=") == 2
    assert '"vmid"' in out


async def test_describe_hidden_looks_like_unknown(as_local):
    with pytest.raises(RouterError) as hidden:
        await handle_meta("describe_tool_input", {"tool_names": ["delete_vm"]}, _Exec())
    with pytest.raises(RouterError) as unknown:
        await handle_meta("describe_tool_input", {"tool_names": ["delete_vmx"]}, _Exec())
    assert str(hidden.value) == "Unknown tool: delete_vm"
    assert str(unknown.value) == "Unknown tool: delete_vmx"


async def test_describe_mixed_and_limits(as_local):
    out = await handle_meta(
        "describe_tool_input", {"tool_names": ["list_vms", "vm_agent_exec"]}, _Exec()
    )
    assert '<input_schema tool="list_vms">' in out and "Unknown tool: vm_agent_exec" in out
    with pytest.raises(RouterError):
        await handle_meta("describe_tool_input", {"tool_names": ["list_vms"] * 11}, _Exec())
    with pytest.raises(RouterError):
        await handle_meta("describe_tool_input", {"tool_names": ['x"><script']}, _Exec())


# ----------------------------------------------------------------------------- execute


async def test_execute_valid(as_local):
    ex = _Exec()
    args = {"node": "pve01", "vmid": 101}
    assert (
        await handle_meta("execute_tool", {"name": "get_vm_config", "arguments": args}, ex) == "ok"
    )
    assert ex.calls == [("get_vm_config", args)]


async def test_execute_unknown(as_local):
    ex = _Exec()
    with pytest.raises(RouterError, match="Unknown tool: nope"):
        await handle_meta("execute_tool", {"name": "nope", "arguments": {}}, ex)
    assert ex.calls == []


async def test_execute_invalid_input(as_local):
    ex = _Exec()
    with pytest.raises(
        RouterError, match="Invalid input for tool get_vm_config: .*missing required"
    ):
        await handle_meta(
            "execute_tool", {"name": "get_vm_config", "arguments": {"node": "pve01"}}, ex
        )
    with pytest.raises(RouterError, match="expected integer"):
        await handle_meta(
            "execute_tool",
            {"name": "get_vm_config", "arguments": {"node": "pve01", "vmid": "101"}},
            ex,
        )
    with pytest.raises(RouterError, match="unknown property"):
        await handle_meta(
            "execute_tool",
            {"name": "get_vm_config", "arguments": {"node": "pve01", "vmid": 101, "x": 1}},
            ex,
        )
    assert ex.calls == []


async def test_execute_hidden_tool_goes_to_policy_unvalidated(as_local):
    # The authoritative check (and its audit line) lives in execute; the router does not
    # leak schema details for a tool the caller cannot see.
    ex = _Exec()
    await handle_meta("execute_tool", {"name": "delete_vm", "arguments": {"bogus": 1}}, ex)
    assert ex.calls == [("delete_vm", {"bogus": 1})]


async def test_execute_meta_shape(as_local):
    with pytest.raises(RouterError):
        await handle_meta("execute_tool", {"arguments": {}}, _Exec())
    with pytest.raises(RouterError):
        await handle_meta("execute_tool", {"name": "list_vms", "arguments": []}, _Exec())
    with pytest.raises(RouterError, match="Unknown tool"):
        await handle_meta("list_vms", {}, _Exec())


# ----------------------------------------------------------------------------- validator


def test_validate_types_and_bools():
    validate_arguments("get_vm_config", {"node": "pve01", "vmid": 100, "current": True})
    with pytest.raises(ValueError, match="expected integer"):
        validate_arguments("get_vm_config", {"node": "pve01", "vmid": True})
    with pytest.raises(ValueError, match="expected boolean"):
        validate_arguments("get_vm_config", {"node": "pve01", "vmid": 100, "current": 1})
    with pytest.raises(ValueError, match="expected object"):
        validate_arguments("get_vm_config", "nope")
    with pytest.raises(ValueError, match="Unknown tool"):
        validate_arguments("nope", {})
    validate_arguments("list_nodes", None)


def test_validate_arrays():
    base = {
        "node": "pve01",
        "names": ["a"],
        "image": "local:import/x.qcow2",
        "ssh_public_keys": "k",
    }
    validate_arguments("deploy_cloud_vms", base)
    with pytest.raises(ValueError, match=r"names\[0\]: expected string"):
        validate_arguments("deploy_cloud_vms", {**base, "names": [1]})


def test_validate_freeform_extra_config():
    ok = {"node": "pve01", "extra_config": {"net4": "virtio,bridge=vmbr1", "cores": 2}}
    validate_arguments("create_vm", ok)
    with pytest.raises(ValueError, match="must be a string, number or boolean"):
        validate_arguments("create_vm", {"node": "pve01", "extra_config": {"a": {"b": 1}}})
    with pytest.raises(ValueError, match="bad property name"):
        validate_arguments("create_vm", {"node": "pve01", "extra_config": {"a b": "x"}})


@pytest.mark.parametrize(
    "tool,args",
    [
        ("get_node_status", {"node": "../cluster"}),
        ("get_node_status", {"node": "pve01/../x"}),
        ("get_node_status", {"node": "pve01?x=1"}),
        ("get_node_status", {"node": "pve%2F01"}),
        ("get_node_status", {"node": "pve01#"}),
        ("get_node_status", {"node": "pve\n01"}),
        ("get_node_status", {"node": ""}),
        ("get_vm_config", {"node": "pve01", "vmid": 5}),
        ("get_vm_snapshot_config", {"node": "pve01", "vmid": 100, "snapname": "a/b"}),
        ("get_task_status", {"node": "pve01", "upid": "UPID:../x"}),
        ("get_pool", {"poolid": "a/b"}),
        (
            "get_storage_volume_info",
            {"node": "pve01", "storage": "local", "volume": "local:../../etc"},
        ),
        ("get_user", {"userid": "a@b/c"}),
        ("get_node_status", {"node": "pve\x0001"}),
    ],
)
def test_path_params_rejected(tool, args):
    with pytest.raises(ValueError, match=f"Invalid input for tool {tool}"):
        validate_arguments(tool, args)


@pytest.mark.parametrize(
    "tool,args",
    [
        (
            "get_task_status",
            {
                "node": "pve-01",
                "upid": "UPID:pve01:0001A2B3:01C2D3E4:6710A1B2:vzdump:100:alice@pve!mcp:",
            },
        ),
        (
            "get_storage_volume_info",
            {"node": "pve01", "storage": "local", "volume": "local:iso/ubuntu-24.04.iso"},
        ),
        ("get_ha_resource", {"sid": "vm:100"}),
        ("update_pool", {"poolid": "prod", "storage": "local,local-lvm"}),
        ("update_backup_job", {"id": "backup-1a2b", "vmid": "100,101"}),
        ("delete_firewall_ipset_entry", {"name": "trusted", "cidr": "192.0.2.0/24"}),
        ("get_user", {"userid": "alice@pve"}),
    ],
)
def test_path_params_accepted(tool, args):
    validate_arguments(tool, args)


@pytest.mark.parametrize(
    "tool,args",
    [
        ("create_vm", {"node": "pve01", "extra_config": {"cipassword": "x"}}),
        ("create_vm", {"node": "pve01", "extra_config": {"CIPASSWORD": "x"}}),
        (
            "create_container",
            {"node": "pve01", "vmid": 200, "ostemplate": "local:vztmpl/x.tar.zst", "password": "x"},
        ),
        ("deploy_fortigate_vm", {"node": "pve01", "image_url": "http://192.0.2.1/x.qcow2"}),
    ],
)
def test_refused_arguments(tool, args):
    with pytest.raises(ValueError, match="not accepted through MCP"):
        validate_arguments(tool, args)
