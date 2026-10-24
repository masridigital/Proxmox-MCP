"""deploy/plan.py: the deployment file is validated strictly and the plan is safe for agents."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "deploy" / "provision.example.toml"
_spec = importlib.util.spec_from_file_location("deploy_plan", ROOT / "deploy" / "plan.py")
plan = importlib.util.module_from_spec(_spec)
sys.modules["deploy_plan"] = plan  # dataclasses resolve types through sys.modules
_spec.loader.exec_module(plan)

REAL_IDS = {
    "0000000000000000000000000000000000000000000000000000000000000000": "a" * 64,
    "00000000000000000000000000000000": "b" * 32,
    "00000000-0000-0000-0000-000000000000": "12345678-1234-1234-1234-123456789abc",
}


def _filled(tmp_path: Path, edit=lambda s: s) -> Path:
    text = EXAMPLE.read_text()
    for old, new in REAL_IDS.items():
        text = text.replace(f'"{old}"', f'"{new}"')
    path = tmp_path / "provision.toml"
    path.write_text(edit(text))
    return path


def test_example_file_is_valid_with_placeholders():
    assert plan.main([str(EXAMPLE), "--allow-placeholders"]) == 0


def test_example_placeholders_are_refused_without_the_flag(capsys):
    assert plan.main([str(EXAMPLE)]) == 2
    assert "still the example placeholder" in capsys.readouterr().err


def test_example_file_holds_only_documentation_values():
    text = EXAMPLE.read_text()
    for host in re.findall(r'"([a-z0-9.-]+\.[a-z]{2,})"', text):
        assert host.endswith(("example.com", "example.internal", ".exe", ".msi")), host
    for ip in re.findall(r"\b(\d+\.\d+\.\d+\.\d+)", text):
        assert ip.startswith("192.0.2."), ip


def test_secret_steps_are_human_only(tmp_path, capsys):
    assert plan.main([str(_filled(tmp_path)), "--json"]) == 0
    steps = json.loads(capsys.readouterr().out)["steps"]
    secret = [s for s in steps if s["secret"]]
    assert {s["id"] for s in secret} >= {"token-alice", "cloudflare", "escrow", "audit-shipping"}
    assert all(s["runner"] == "human" for s in secret)


def test_plan_never_contains_a_secret_value(tmp_path, capsys):
    plan.main([str(_filled(tmp_path)), "--json"])
    out = capsys.readouterr().out
    assert "CF_API_TOKEN=" not in out and "PVEAPIToken" not in out
    assert not re.search(r"![a-z0-9]+=[0-9a-f-]{36}", out)


def test_env_exports_are_quoted(tmp_path, capsys):
    plan.main([str(_filled(tmp_path)), "--env"])
    lines = capsys.readouterr().out.splitlines()
    assert lines and all(re.fullmatch(r"export [A-Z_]+='[^']*'", line) for line in lines)
    assert "export BROKER_MODE='access'" in lines


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda s: s.replace('broker_mode = "access"', 'broker_mode = "direct"'), "broker_mode"),
        (lambda s: s.replace('short = "alice"', 'short = "root"'), "short"),
        (lambda s: s.replace('mode = "ro"', 'mode = "rw"'), "allow_admin_tools"),
        (
            lambda s: s.replace('email = "alice@example.com"', 'email = "Alice@Example.com"'),
            "email",
        ),
        (lambda s: s.replace("phi_in_scope = false", "phi_in_scope = true"), "BAA"),
        (
            lambda s: s.replace('proxmox_addresses = ["192.0.2.10/32"]', "proxmox_addresses = []"),
            "proxmox_addresses",
        ),
        (
            lambda s: s.replace('custodian_b = "Custodian B"', 'custodian_b = "Custodian A"'),
            "custodians",
        ),
        (lambda s: s + '\n[extra]\nkey = "x"\n', "unknown section"),
        (
            lambda s: s.replace(
                'host = "pve.example.internal"', 'host = "pve.example.internal; rm -rf /"'
            ),
            "host",
        ),
        (
            lambda s: (
                s + '\n[[users]]\nemail = "alice@example.com"\nshort = "alice2"\nmode = "ro"\n'
            ),
            "unique",
        ),
    ],
)
def test_invalid_files_are_refused(tmp_path, capsys, edit, message):
    assert plan.main([str(_filled(tmp_path, edit))]) == 2
    assert message in capsys.readouterr().err


def test_real_deployment_file_is_git_ignored():
    assert "deploy/provision.toml" in (ROOT / ".gitignore").read_text().splitlines()
