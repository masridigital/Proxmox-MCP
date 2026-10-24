"""End-to-end broker behaviour beyond the per-tool matrix.

Same harness as test_e2e_matrix.py: the real broker app, Worker-signed requests,
a temp credentials directory and a recording mock of the Proxmox API.
"""

from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fixtures.broker import MODES, UNENROLLED, USERS, audit_lines, running_broker
from fixtures.gen_upstream_calls import tool_def_sha256
from fixtures.tool_args import minimal_args

from proxmox_mcp import policy, router

UPSTREAM = json.loads((Path(__file__).parent / "fixtures" / "upstream_calls.json").read_text())
TIERS_FOR = {"ro": {"read"}, "operator": {"read", "operate"}, "rw": {"read", "operate", "admin"}}
ADMIN_TOOLS = sorted(t for t in router.REGISTRY if policy.tool_tier(t) == "admin")


@pytest.fixture(scope="module")
def broker(tmp_path_factory):
    with running_broker(tmp_path_factory.mktemp("e2e-broker")) as b:
        yield b


@pytest.fixture
def b(broker):
    broker.proxmox.reset()
    return broker


# ---- upstream identity -----------------------------------------------------------


def test_registry_is_upstream_catalog():
    """Same 340 tools, each definition byte-for-byte the upstream one."""
    upstream = UPSTREAM["tools"]
    assert set(router.REGISTRY) == set(upstream)
    changed = [
        name
        for name, (tool_def, _) in router.REGISTRY.items()
        if tool_def_sha256(tool_def) != upstream[name]["tool_sha256"]
    ]
    assert changed == []


def test_upstream_reference_is_reproducible():
    """upstream_calls.json still matches the upstream modules taken from git history."""
    root = Path(__file__).resolve().parents[1]
    have = subprocess.run(
        ["git", "cat-file", "-e", "a63576c:proxmox_mcp/tools/qemu.py"],  # noqa: S607
        cwd=root,
        capture_output=True,
    )
    if have.returncode != 0:
        pytest.skip("upstream import commit a63576c is not in this clone (shallow checkout)")
    gen = root / "tests" / "fixtures" / "gen_upstream_calls.py"
    result = subprocess.run(
        [sys.executable, str(gen), "--check"], cwd=root, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_agent_card_matches_policy():
    """agent-card.json lists every non-forbidden tool with its tier, and nothing else."""
    card = json.loads((Path(__file__).resolve().parents[1] / "agent-card.json").read_text())
    listed = {c["name"]: c["tier"] for s in card["skills"] for c in s["capabilities"]}
    expected = {t: policy.tool_tier(t) for t in router.REGISTRY}
    assert listed == {t: tier for t, tier in expected.items() if tier != "forbidden"}


def test_registry_keeps_upstream_module_grouping():
    assert {n: m.__name__.rsplit(".", 1)[-1] for n, (_, m) in router.REGISTRY.items()} == {
        n: e["module"] for n, e in UPSTREAM["tools"].items()
    }


# ---- catalog ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
def test_catalog_per_mode(b, mode):
    r = b.worker.catalog(USERS[mode].email)
    assert r.status_code == 200
    doc = r.json()
    assert doc["mode"] == mode
    tools = {t["name"]: t for t in doc["tools"]}
    expected = {t for t in router.REGISTRY if policy.tool_tier(t) in TIERS_FOR[mode]}
    assert set(tools) == expected
    for name, entry in tools.items():
        assert entry["tier"] == policy.tool_tier(name)
        served = {k: entry[k] for k in ("name", "description", "inputSchema")}
        assert tool_def_sha256(served) == UPSTREAM["tools"][name]["tool_sha256"]
    assert b.proxmox.requests == []


def test_catalog_never_lists_forbidden(b):
    names = {t["name"] for t in b.worker.catalog(USERS["rw"].email).json()["tools"]}
    assert not any(policy.tool_tier(n) == "forbidden" for n in names)


# ---- authentication and enrollment ------------------------------------------------------


def test_unenrolled_user_is_refused(b):
    assert b.worker.catalog(UNENROLLED).status_code == 403
    r = b.worker.execute(UNENROLLED, "list_nodes", {})
    assert r.status_code == 403 and r.json() == {"error": "forbidden"}
    assert b.proxmox.requests == []


def test_wrong_host_is_refused(b):
    body = json.dumps({"tool": "list_nodes", "arguments": {}}).encode()
    headers = b.worker._headers(USERS["ro"].email, body, "POST", "/v1/execute")
    headers.update({"host": "evil.example.net", "content-type": "application/json"})
    assert b.worker.http.post("/v1/execute", content=body, headers=headers).status_code == 421
    assert b.proxmox.requests == []


def test_replayed_request_runs_once(b):
    body = json.dumps({"tool": "list_nodes", "arguments": {}}).encode()
    headers = b.worker._headers(USERS["ro"].email, body, "POST", "/v1/execute")
    headers["content-type"] = "application/json"
    assert b.worker.http.post("/v1/execute", content=body, headers=headers).status_code == 200
    assert b.worker.http.post("/v1/execute", content=body, headers=headers).status_code == 401
    assert len(b.proxmox.requests) == 1


def test_assertion_for_one_user_cannot_carry_another_users_body(b):
    """The identity is bound to the body: swapping the body after signing fails."""
    signed = json.dumps({"tool": "list_nodes", "arguments": {}}).encode()
    sent = json.dumps({"tool": "start_vm", "arguments": {"node": "pve1", "vmid": 100}}).encode()
    headers = b.worker._headers(USERS["operator"].email, signed, "POST", "/v1/execute")
    headers["content-type"] = "application/json"
    assert b.worker.http.post("/v1/execute", content=sent, headers=headers).status_code == 401
    assert b.proxmox.requests == []


# ---- per-user tokens under concurrency ----------------------------------------------------


def test_tokens_never_cross_between_concurrent_users(b):
    vmid_for = {"ro": 101, "operator": 102, "rw": 103}

    def call(mode: str) -> bool:
        r = b.worker.execute(
            USERS[mode].email, "get_vm_status", {"node": "pve1", "vmid": vmid_for[mode]}
        )
        return r.json()["ok"]

    jobs = [mode for _ in range(15) for mode in MODES]
    with ThreadPoolExecutor(max_workers=9) as pool:
        assert all(pool.map(call, jobs))
    seen = b.proxmox.requests
    assert len(seen) == len(jobs)
    for mode in MODES:
        mine = [s for s in seen if s.path == f"/nodes/pve1/qemu/{vmid_for[mode]}/status/current"]
        assert len(mine) == 15
        assert {s.authorization for s in mine} == {USERS[mode].authorization}


# ---- write controls ----------------------------------------------------------------------


def test_phi_in_a_write_is_refused_before_proxmox(b):
    r = b.worker.execute(
        USERS["rw"].email,
        "set_vm_config",
        {"node": "pve1", "vmid": 100, "description": "patient DOB: 01/02/1960"},
    )
    assert r.json()["ok"] is False and "possible PHI detected (dob)" in r.json()["text"]
    assert b.proxmox.requests == []
    out = [x for x in audit_lines() if x.get("event") == "proxmox"]
    assert [(x["status"], x["deny"]) for x in out] == [("denied", "possible PHI detected (dob)")]
    assert "1960" not in json.dumps(audit_lines())


@pytest.mark.parametrize(
    "tool,args",
    [
        ("create_vm", {"node": "pve1", "extra_config": {"cipassword": "x"}}),
        (
            "create_container",
            {"node": "pve1", "ostemplate": "local:vztmpl/a.tar.zst", "password": "x"},
        ),
        ("deploy_fortigate_vm", {"node": "pve1", "image_url": "https://example.com/fgt.qcow2"}),
    ],
)
def test_guest_secrets_and_url_downloads_are_refused(b, tool, args):
    r = b.worker.execute(USERS["rw"].email, tool, args)
    assert r.json()["ok"] is False and "is not accepted through MCP" in r.json()["text"]
    assert b.proxmox.requests == []


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Upstream regression: set_vm_config promises 'Accepts any Proxmox VM config key', "
        "and upstream forwarded every key; router.validate_arguments rejects keys the "
        "schema does not list (balloon, numa, net2, ...). Fix is in proxmox_mcp/router.py."
    ),
)
def test_set_vm_config_accepts_undeclared_config_keys(b):
    r = b.worker.execute(
        USERS["rw"].email, "set_vm_config", {"node": "pve1", "vmid": 100, "balloon": 1024}
    )
    assert r.json()["ok"] is True, r.json()["text"]
    assert [s.call() for s in b.proxmox.requests] == [
        ["PUT", "/nodes/pve1/qemu/100/config", [["balloon", "1024"]]]
    ]


# ---- MCP_ALLOW_ADMIN_TOOLS=0 ---------------------------------------------------------------


@pytest.fixture(scope="module")
def broker_no_admin(tmp_path_factory):
    with running_broker(tmp_path_factory.mktemp("e2e-noadmin"), admin_tools=False) as b:
        yield b


@pytest.mark.parametrize("tool", ADMIN_TOOLS)
def test_admin_tools_off_by_default_even_for_rw(broker_no_admin, tool):
    b = broker_no_admin
    b.proxmox.reset()
    r = b.worker.execute(USERS["rw"].email, tool, minimal_args(tool, router.REGISTRY[tool][0]))
    assert r.json()["ok"] is False
    assert "MCP_ALLOW_ADMIN_TOOLS" in r.json()["text"]
    assert b.proxmox.requests == []
    names = {t["name"] for t in b.worker.catalog(USERS["rw"].email).json()["tools"]}
    assert tool not in names
