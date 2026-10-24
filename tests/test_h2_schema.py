"""H2 red team: schema-validator bypasses and host-access config smuggling."""

from __future__ import annotations

import json

import pytest

from proxmox_mcp import router
from proxmox_mcp.identity import Identity, current_identity
from proxmox_mcp.router import RouterError, handle_meta, validate_arguments

VM = {"node": "pve01", "vmid": 100}
CT_CREATE = {"node": "pve01", "vmid": 200, "ostemplate": "local:vztmpl/debian.tar.zst"}


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
    monkeypatch.setenv("MCP_LOCAL_MODE", "rw")
    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "1")


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


# ----------------------------------------------------------------------------- types


@pytest.mark.parametrize("value", [10**30, -(10**30), 2**53 + 1])
def test_huge_integers_refused(value):
    with pytest.raises(ValueError):
        validate_arguments("set_vm_config", {**VM, "memory": value})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_refused_in_freeform(value):
    with pytest.raises(ValueError):
        validate_arguments("create_vm", {"node": "pve01", "extra_config": {"balloon": value}})


def test_numeric_strings_and_bool_as_int_refused():
    with pytest.raises(ValueError, match="expected integer"):
        validate_arguments("get_vm_status", {"node": "pve01", "vmid": "100"})
    with pytest.raises(ValueError, match="expected integer"):
        validate_arguments("get_vm_status", {"node": "pve01", "vmid": True})
    with pytest.raises(ValueError, match="expected integer"):
        validate_arguments("get_vm_status", {"node": "pve01", "vmid": 100.0})
    with pytest.raises(ValueError, match="expected boolean"):
        validate_arguments("get_vm_config", {**VM, "current": 1})


def test_very_long_strings_refused():
    with pytest.raises(ValueError):
        validate_arguments("set_vm_config", {**VM, "description": "a" * 70000})


def test_pattern_dollar_does_not_accept_trailing_newline():
    assert router._check is not None
    with pytest.raises(RouterError):
        router._check("list_vms\n", router._TOOL_NAME, "x")


@pytest.mark.parametrize("key", ["tags", "net0", "boot", "name", "cpu", "startup"])
def test_control_characters_refused_in_config_values(key):
    # Newlines in a single-line value could inject a line into the guest config file.
    with pytest.raises(ValueError):
        validate_arguments("set_vm_config", {**VM, key: "vmbr0\nhookscript: local:snippets/x.sh"})
    with pytest.raises(ValueError):
        validate_arguments("set_vm_config", {**VM, key: "a\rb"})


def test_multiline_allowed_where_legitimate():
    validate_arguments("set_vm_config", {**VM, "description": "line one\nline two"})
    validate_arguments(
        "deploy_cloud_vms",
        {
            "node": "pve01",
            "names": ["a1"],
            "image": "local:import/x.qcow2",
            "ssh_public_keys": "ssh-ed25519 AAAA a\nssh-ed25519 BBBB b",
        },
    )


# ----------------------------------------------------------------------------- nesting / DoS


def _deep(n):
    v: object = 1
    for _ in range(n):
        v = {"a": v}
    return v


async def test_execute_tool_deep_nesting_is_refused_without_recursion(as_local):
    ex = _Exec()
    with pytest.raises(RouterError):
        await handle_meta(
            "execute_tool", {"name": "list_vms", "arguments": {"node": _deep(5000)}}, ex
        )
    # Hidden tools also go through the structural guard before reaching execute.
    with pytest.raises(RouterError):
        await handle_meta(
            "execute_tool", {"name": "vm_agent_exec", "arguments": {"x": _deep(5000)}}, ex
        )
    assert ex.calls == []


async def test_execute_tool_huge_argument_fanout_refused(as_local):
    ex = _Exec()
    args = {f"k{i}": "x" for i in range(5000)}
    with pytest.raises(RouterError):
        await handle_meta("execute_tool", {"name": "vm_agent_exec", "arguments": args}, ex)
    assert ex.calls == []


async def test_execute_tool_accepts_array_arguments(as_local):
    # Dynamic mode must not reject a tool whose schema has arrays (deploy_cloud_vms).
    ex = _Exec()
    args = {
        "node": "pve01",
        "names": ["a1"],
        "image": "local:import/x.qcow2",
        "ssh_public_keys": "ssh-ed25519 A",
    }
    assert (
        await handle_meta("execute_tool", {"name": "deploy_cloud_vms", "arguments": args}, ex)
        == "ok"
    )


async def test_execute_tool_nested_object_in_arguments_still_validated(as_local):
    ex = _Exec()
    with pytest.raises(RouterError, match="expected string"):
        await handle_meta(
            "execute_tool", {"name": "get_node_status", "arguments": {"node": {"a": 1}}}, ex
        )
    with pytest.raises(RouterError, match="must be a string, number or boolean"):
        await handle_meta(
            "execute_tool",
            {"name": "create_vm", "arguments": {"node": "pve01", "extra_config": {"a": [1]}}},
            ex,
        )
    assert ex.calls == []


def test_unsupported_schema_combinators_fail_closed():
    with pytest.raises(RouterError):
        router._check("x", {"anyOf": [{"type": "string"}]}, "a")
    with pytest.raises(RouterError):
        router._check("x", {"oneOf": [{"type": "string"}]}, "a")


def test_no_tool_schema_uses_unsupported_keywords():
    allowed = {
        "type",
        "properties",
        "required",
        "description",
        "items",
        "enum",
        "additionalProperties",
        "minimum",
        "maximum",
        "maxLength",
        "minLength",
        "pattern",
        "maxItems",
        "minItems",
        "default",
    }

    def walk(schema, where):
        bad = set(schema) - allowed
        assert not bad, (where, bad)
        for k, sub in (schema.get("properties") or {}).items():
            walk(sub, f"{where}.{k}")
        if isinstance(schema.get("items"), dict):
            walk(schema["items"], f"{where}[]")

    for name, (tool_def, _) in router.REGISTRY.items():
        walk(tool_def["inputSchema"], name)


def test_duplicate_json_keys_are_irrelevant_to_validation():
    # The router receives a dict; JSON duplicate-key ambiguity is a transport concern
    # (last wins in both Python and JS). Document the effect: validation sees the final value.
    args = json.loads('{"node": "pve01", "vmid": 100, "vmid": 5}')
    with pytest.raises(ValueError):
        validate_arguments("get_vm_status", args)


# ----------------------------------------------------------------------------- host access


HOST_ACCESS_EXTRA = [
    {"hookscript": "local:snippets/x.sh"},
    {"args": "-device virtio-9p-pci"},
    {"ARGS": "-x"},
    {"cicustom": "user=local:snippets/u.yaml"},
    {"hostpci0": "0000:01:00.0"},
    {"usb0": "host=1234:5678"},
    {"serial1": "/dev/ttyS0"},
    {"parallel0": "/dev/parport0"},
    {"virtiofs0": "dirid=share"},
    {"ivshmem": "size=32"},
    {"rng0": "source=/dev/hwrng"},
    {"affinity": "0-3"},
    {"scsi5": "/dev/sdb"},
    {"virtio1": "file=/dev/sdc"},
    {"sata0": "local-lvm:0,import-from=/etc/shadow"},
    {"efidisk0": "/var/lib/x.raw"},
    {"ide0": "cdrom,media=cdrom"},
    {"cipassword": "x"},
    {"lxc.apparmor.profile": "unconfined"},
]


@pytest.mark.parametrize("extra", HOST_ACCESS_EXTRA)
def test_extra_config_host_access_refused(extra):
    with pytest.raises(ValueError):
        validate_arguments("create_vm", {"node": "pve01", "vmid": 100, "extra_config": extra})


def test_extra_config_benign_keys_allowed():
    validate_arguments(
        "create_vm",
        {
            "node": "pve01",
            "vmid": 100,
            "extra_config": {
                "net4": "virtio,bridge=vmbr1",
                "ciuser": "ubuntu",
                "ipconfig0": "ip=dhcp",
                "serial0": "socket",
                "scsi2": "local-lvm:8",
                "efidisk0": "local-lvm:1,efitype=4m",
                "balloon": 0,
            },
        },
    )


@pytest.mark.parametrize(
    "key,value",
    [
        ("scsi0", "/dev/sda"),
        ("scsi0", "local-lvm:0,import-from=/dev/sda"),
        ("ide2", "/root/x.iso,media=cdrom"),
        ("ide2", "cdrom"),
        ("serial0", "/dev/ttyS0"),
        ("scsi1", "volume=/dev/sdb"),
    ],
)
def test_create_vm_top_level_host_devices_refused(key, value):
    with pytest.raises(ValueError):
        validate_arguments("create_vm", {"node": "pve01", "vmid": 100, key: value})


def test_set_vm_config_host_devices_refused():
    with pytest.raises(ValueError):
        validate_arguments("set_vm_config", {**VM, "scsi0": "/dev/sda"})
    validate_arguments("set_vm_config", {**VM, "scsi0": "local-lvm:vm-100-disk-0,size=32G"})
    validate_arguments("set_vm_config", {**VM, "ide2": "local:iso/x.iso,media=cdrom"})
    validate_arguments("set_vm_config", {**VM, "ide2": "none,media=cdrom"})


@pytest.mark.parametrize(
    "tool,args",
    [
        ("create_container", {**CT_CREATE, "unprivileged": False}),
        ("create_container", {**CT_CREATE, "rootfs": "/srv/rootfs"}),
        ("create_container", {**CT_CREATE, "features": "mount=nfs"}),
        ("create_container", {**CT_CREATE, "ostemplate": "/var/lib/vz/template/x.tar.zst"}),
        ("set_container_config", {**VM, "mp0": "/srv/host,mp=/data"}),
        ("set_container_config", {**VM, "mp0": "volume=/srv/host,mp=/data"}),
        ("set_container_config", {**VM, "unprivileged": False}),
        ("set_container_config", {**VM, "features": "nesting=1,mount=cifs"}),
        (
            "restore_container_backup",
            {
                "node": "pve01",
                "vmid": 200,
                "ostemplate": "local:backup/x.tar.zst",
                "unprivileged": False,
            },
        ),
        (
            "restore_vm_backup",
            {"node": "pve01", "vmid": 200, "archive": "/var/lib/vz/dump/x.vma.zst"},
        ),
        ("import_vm_disk", {**VM, "source": "/dev/sda", "storage": "local-lvm"}),
        (
            "import_vm_disk",
            {**VM, "source": "local:import/x.qcow2", "storage": "local-lvm", "disk": "args"},
        ),
        (
            "import_vm_disk",
            {**VM, "source": "local:import/x.qcow2", "storage": "local-lvm", "disk": "hookscript"},
        ),
        (
            "import_vm_disk",
            {
                **VM,
                "source": "local:import/x.qcow2",
                "storage": "local-lvm",
                "options": "discard=on,file=/dev/sda",
            },
        ),
        (
            "import_vm_disk",
            {**VM, "source": "local:import/x.qcow2,file=/dev/sda", "storage": "local-lvm"},
        ),
        (
            "import_vm_disk",
            {**VM, "source": "local:import/x.qcow2", "storage": "local-lvm:0,import-from=/dev/sda"},
        ),
        ("set_cluster_options", {"migration_type": "insecure"}),
        ("migrate_vm", {**VM, "target": "pve02", "migration_type": "insecure"}),
    ],
)
def test_host_access_and_downgrades_refused(tool, args):
    with pytest.raises(ValueError):
        validate_arguments(tool, args)


def test_container_benign_config_allowed():
    validate_arguments(
        "create_container",
        {
            **CT_CREATE,
            "unprivileged": True,
            "features": "nesting=1,keyctl=1",
            "rootfs": "local-lvm:8",
        },
    )
    validate_arguments("set_container_config", {**VM, "mp0": "local-lvm:10,mp=/data"})
    validate_arguments(
        "import_vm_disk",
        {
            **VM,
            "source": "local:import/x.qcow2",
            "storage": "local-lvm",
            "disk": "scsi1",
            "options": "discard=on,ssd=1",
        },
    )


@pytest.mark.parametrize(
    "key,value",
    [
        ("disk_storage", "local-lvm:0,import-from=/dev/sda,x"),
        ("bridge", "vmbr0,firewall=0"),
        ("image", "local:import/x.qcow2,discard=on"),
        ("image", "/dev/sda"),
        ("names", ["ok1", "bad,name"]),
        ("ip_addresses", ["fe80::1%a,gw=192.0.2.1/64"]),
        ("ciuser", "root\nx"),
        ("nameserver", "192.0.2.1,x=y"),
        ("tags", "a,b=c"),
    ],
)
def test_deploy_cloud_vms_property_string_injection_refused(key, value):
    base = {
        "node": "pve01",
        "names": ["vm1"],
        "image": "local:import/x.qcow2",
        "ssh_public_keys": "ssh-ed25519 A",
    }
    if key == "ip_addresses":
        base["names"] = ["vm1"]
    with pytest.raises(ValueError):
        validate_arguments("deploy_cloud_vms", {**base, key: value})


@pytest.mark.parametrize(
    "key,value",
    [
        ("disk_storage", "local-lvm:0,import-from=/dev/sda"),
        ("wan_bridge", "vmbr0,link_down=1"),
        ("lan_bridge", "vmbr1,tag=5"),
        ("extra_nics", ["vmbr1:160,firewall=0"]),
        ("extra_nics", ["vmbr1:x"]),
        ("image", "/dev/sda"),
    ],
)
def test_deploy_fortigate_property_string_injection_refused(key, value):
    base = {"node": "pve01", "image": "local:import/fortios.qcow2"}
    with pytest.raises(ValueError):
        validate_arguments("deploy_fortigate_vm", {**base, key: value})


def test_deploy_benign_values_allowed():
    validate_arguments(
        "deploy_fortigate_vm",
        {
            "node": "pve01",
            "image": "local:import/fortios.qcow2",
            "wan_bridge": "vmbr0",
            "lan_bridge": "vmbr1",
            "extra_nics": ["vmbr2", "vmbr3:160"],
            "disk_storage": "local-lvm",
        },
    )
    validate_arguments(
        "deploy_cloud_vms",
        {
            "node": "pve01",
            "names": ["k3s-1", "k3s-2"],
            "image": "local:import/noble.qcow2",
            "ssh_public_keys": "ssh-ed25519 A",
            "ip_addresses": ["192.0.2.21/24", "2001:db8::5/64"],
            "gateway": "192.0.2.1",
            "nameserver": "192.0.2.53 192.0.2.54",
            "searchdomain": "example.internal",
            "ciuser": "ubuntu",
            "tags": "k3s;test",
            "bridge": "vmbr0",
            "disk_storage": "local-lvm",
        },
    )


def test_acme_tos_directory_is_not_an_ssrf_primitive():
    validate_arguments(
        "get_acme_tos", {"directory": "https://acme-v02.api.letsencrypt.org/directory"}
    )
    for bad in (
        "http://192.0.2.1:8080/",
        "https://169.254.169.254/latest",
        "file:///etc/passwd",
        "https://acme-v02.api.letsencrypt.org.evil.example/directory",
    ):
        with pytest.raises(ValueError):
            validate_arguments("get_acme_tos", {"directory": bad})
