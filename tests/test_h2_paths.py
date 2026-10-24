"""H2 red team: no hostile value can reach a Proxmox URL path, for any tool.

Method: a recording fake client runs every handler. Marker tracing finds every argument a
handler interpolates into a path; the router's PATH_KEYS table must equal that trace, and
every hostile payload in every argument (path keys and everything else) must either be
refused by router.validate_arguments or provably not reach a path.
"""

from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote

import pytest

from proxmox_mcp import outbound, router


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []

    async def request(self, method, path, data=None):
        self.calls.append((method, path, data))
        if "/tasks/" in path and path.endswith("/status"):
            return {"data": {"status": "stopped", "exitstatus": "OK"}}
        if path == "/cluster/nextid":
            return {"data": "100"}
        if path == "/cluster/resources":
            return {"data": []}
        if path.endswith("/config"):
            return {"data": {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"}}
        return {"data": "UPID:pve01:00000001:00000002:00000003:qmcreate:100:alice@pve:"}

    async def get(self, path, params=None):
        return await self.request("GET", path, params)

    async def post(self, path, data=None):
        return await self.request("POST", path, data)

    async def put(self, path, data=None):
        return await self.request("PUT", path, data)

    async def delete(self, path, params=None):
        return await self.request("DELETE", path, params)


async def _no_sleep(_seconds):
    return None


def run_handler(name: str, args: dict[str, Any]) -> Recorder:
    _, mod = router.REGISTRY[name]
    rec = Recorder()

    async def go():
        orig = asyncio.sleep
        asyncio.sleep = _no_sleep  # appliance tools poll tasks
        try:
            await mod.handle(name, args, rec)
        except Exception:  # a refusal inside the handler is fine; recorded calls count
            pass
        finally:
            asyncio.sleep = orig

    asyncio.run(go())
    return rec


# Valid values per key, so a baseline call passes validation.
VALID: dict[str, Any] = {
    "node": "pve01",
    "target": "pve02",
    "target_node": "pve02",
    "vmid": 100,
    "newid": 101,
    "first_vmid": 200,
    "storage": "local",
    "image_storage": "local",
    "disk_storage": "local-lvm",
    "volume": "local:iso/x.iso",
    "upid": "UPID:pve01:00000001:00000002:00000003:vzdump:100:alice@pve:",
    "userid": "alice@pve",
    "sid": "vm:100",
    "cidr": "192.0.2.0/24",
    "subnet": "zone1-192.0.2.0-24",
    "snapname": "snap1",
    "poolid": "prod",
    "image": "local:import/x.qcow2",
    "names": ["vm1"],
    "ssh_public_keys": "ssh-ed25519 AAAAC3Nza test",
    "ostemplate": "local:vztmpl/debian.tar.zst",
    "archive": "local:backup/vzdump-qemu-100.vma.zst",
    "source": "local:import/disk.qcow2",
    "disk": "scsi0",
    "size": "+1G",
    "zone": "zone1",
    "vnet": "vnet1",
    "iface": "vmbr0",
    "service": "pveproxy",
    "tokenid": "mcp",
    "realm": "pve",
    "type": "lvm",
    "pos": 0,
    "osdid": 0,
}


def _valid_value(key: str, schema: dict[str, Any]) -> Any:
    if "enum" in schema:
        return schema["enum"][0]
    if key in VALID:
        return VALID[key]
    t = schema.get("type")
    return {"integer": 1, "number": 1, "boolean": True, "array": [], "object": {}}.get(t, "x1")


def baseline(name: str) -> dict[str, Any]:
    schema = router.REGISTRY[name][0]["inputSchema"]
    props = schema.get("properties", {})
    keys = set(schema.get("required", [])) | (router.PATH_KEYS.get(name, frozenset()) & set(props))
    args = {k: _valid_value(k, props.get(k, {})) for k in keys}
    if name == "deploy_fortigate_vm":
        args.setdefault("image", VALID["image"])
    if name == "get_acme_tos":
        args.pop("directory", None)
    return args


def _markers(name: str) -> tuple[dict[str, Any], dict[str, str]]:
    props = router.REGISTRY[name][0]["inputSchema"].get("properties", {})
    args: dict[str, Any] = {}
    markers: dict[str, str] = {}
    for i, (key, schema) in enumerate(props.items()):
        t = schema.get("type")
        if "enum" in schema:
            continue
        if t == "string":
            args[key] = f"mk{i}q"
            markers[f"mk{i}q"] = key
        elif t == "integer":
            args[key] = 700000 + i
            markers[str(700000 + i)] = key
        elif t == "array" and schema.get("items", {}).get("type") == "string":
            args[key] = [f"mk{i}a"]
            markers[f"mk{i}a"] = key
    args.pop("image_url", None)
    for key in ("ip_addresses", "gateway"):
        if name == "deploy_cloud_vms":
            args.pop(key, None)
    return args, markers


def traced_path_keys(name: str) -> frozenset[str]:
    args, markers = _markers(name)
    rec = run_handler(name, args)
    found = set()
    for _, path, _ in rec.calls:
        for segment in path.split("/"):
            for marker, key in markers.items():
                if marker in segment:
                    found.add(key)
    return frozenset(found)


ALL = sorted(router.REGISTRY)


@pytest.mark.parametrize("name", ALL)
def test_path_keys_table_matches_handlers(name):
    assert traced_path_keys(name) == router.PATH_KEYS.get(name, frozenset())


def test_every_path_key_has_a_strict_validator():
    keys = set().union(*router.PATH_KEYS.values())
    missing = sorted(
        k for k in keys if k not in router.PATH_PARAM_PATTERNS and k not in router.INT_PARAM_RANGES
    )
    assert missing == []


@pytest.mark.parametrize("name", ALL)
def test_baseline_is_valid(name):
    router.validate_arguments(name, baseline(name))


HOSTILE = [
    "/",
    "..",
    "a/b",
    "a/../b",
    "a?b=1",
    "a#b",
    "a%2Fb",
    "a%2fb",
    "%2e%2e",
    "a\x00b",
    "a\nb",
    "a b",
    "a\\b",
    "pve01／x",  # fullwidth solidus
    "pve01∕x",  # division slash
    "ｐｖｅ",  # fullwidth letters
    "pveİ",  # Turkish dotted capital I
    "pve01​",  # zero-width space
    ".",
    "a;b",
    "a&b",
    "",
]


def _hostile_cases():
    for name in ALL:
        for key in sorted(router.PATH_KEYS.get(name, ())):
            for payload in HOSTILE:
                if payload == "a/b" and key in ENCODED:
                    continue  # a slash inside a volume id / CIDR is legitimate; it is encoded
                yield name, key, payload


ENCODED = {"volume", "cidr", "subnet"}


@pytest.mark.parametrize("name,key,payload", list(_hostile_cases()))
def test_hostile_path_values_are_refused(name, key, payload):
    args = baseline(name)
    args[key] = payload
    with pytest.raises(ValueError):
        router.validate_arguments(name, args)


@pytest.mark.parametrize(
    "name",
    [n for n in ALL if any(k in router.INT_PARAM_RANGES for k in router.PATH_KEYS.get(n, ()))],
)
def test_negative_and_huge_int_path_values_are_refused(name):
    for key in router.PATH_KEYS[name]:
        if key not in router.INT_PARAM_RANGES:
            continue
        schema = router.REGISTRY[name][0]["inputSchema"]["properties"][key]
        if schema.get("type") != "integer":
            continue
        for bad in (-1, 10**30, True):
            args = baseline(name)
            args[key] = bad
            with pytest.raises(ValueError):
                router.validate_arguments(name, args)


def _all_string_keys(name):
    props = router.REGISTRY[name][0]["inputSchema"].get("properties", {})
    return sorted(
        k for k, s in props.items() if s.get("type") in ("string", "array") and "enum" not in s
    )


@pytest.mark.parametrize("name", ALL)
def test_no_hostile_value_in_any_argument_reaches_a_path(name):
    """End to end: whatever passes validation, every path the handler builds is clean."""
    for key in _all_string_keys(name):
        schema = router.REGISTRY[name][0]["inputSchema"]["properties"][key]
        for payload in HOSTILE:
            args = baseline(name)
            args[key] = [payload] if schema.get("type") == "array" else payload
            try:
                router.validate_arguments(name, args)
            except ValueError:
                continue
            rec = run_handler(name, args)
            for _, path, _ in rec.calls:
                outbound.validate_path(path)
                if len(payload) > 1:
                    assert payload not in path, (name, key, payload, path)
                    if key not in ENCODED and quote(payload, safe="") != payload:
                        assert quote(payload, safe="") not in path, (name, key, payload, path)


def test_deploy_cloud_vms_first_vmid_bounded():
    args = baseline("deploy_cloud_vms")
    for bad in (-5, 0, 99, 10**12):
        with pytest.raises(ValueError):
            router.validate_arguments("deploy_cloud_vms", {**args, "first_vmid": bad})
    router.validate_arguments("deploy_cloud_vms", {**args, "first_vmid": 300})


def test_multi_call_tools_build_only_clean_paths():
    for name, extra in (
        ("deploy_cloud_vms", {"names": ["a1", "a2"], "first_vmid": 300}),
        ("deploy_fortigate_vm", {"vmid": 400, "lan_bridge": "vmbr1", "extra_nics": ["vmbr2:20"]}),
    ):
        args = {**baseline(name), **extra}
        router.validate_arguments(name, args)
        rec = run_handler(name, args)
        assert len(rec.calls) > 2
        for method, path, _ in rec.calls:
            outbound.validate_path(path)
            outbound.check(method, path, "rw")
