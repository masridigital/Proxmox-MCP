"""Regenerate tests/fixtures/upstream_calls.json from the upstream tool modules.

The JSON is the reference for upstream fidelity: for every tool in upstream
ry-ops/proxmox-mcp-server @7276144 (imported in this repo as commit a63576c), the
sha256 of its tool definition and the exact Proxmox calls (method, path,
parameters) its handler makes for the minimal arguments in tool_args.py, against
the canned answers in mock_proxmox.py.

The upstream modules are taken from git, not from the working tree, so later
edits to proxmox_mcp/tools cannot change the reference by accident. Run from the
repository root after changing tool_args.py or mock_proxmox.py:

    .venv/bin/python tests/fixtures/gen_upstream_calls.py [<upstream-commit>]
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = HERE / "upstream_calls.json"
UPSTREAM_COMMIT = "a63576c"
UPSTREAM_MODULES = [
    "nodes",
    "qemu",
    "lxc",
    "storage",
    "cluster",
    "access",
    "firewall",
    "disks",
    "ceph",
    "acme",
    "sdn",
    "notifications",
    "pools",
    "appliances",
]
PKG = "upstream_proxmox_mcp"


def tool_def_sha256(tool_def: dict) -> str:
    canonical = json.dumps(tool_def, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _extract(commit: str, dest: Path) -> None:
    pkg = dest / PKG
    (pkg / "tools").mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "tools" / "__init__.py").write_text("")
    # Upstream tools import ProxmoxClient for type hints only.
    (pkg / "client.py").write_text("class ProxmoxClient:\n    pass\n")
    for mod in UPSTREAM_MODULES:
        src = subprocess.run(
            ["git", "show", f"{commit}:proxmox_mcp/tools/{mod}.py"],  # noqa: S607
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        (pkg / "tools" / f"{mod}.py").write_text(src)


async def _run_all(modules: list) -> dict:
    sys.path.insert(0, str(ROOT / "tests"))
    from fixtures.mock_proxmox import RecordingClient
    from fixtures.tool_args import minimal_args

    tools: dict[str, dict] = {}
    for mod in modules:
        for tool_def in mod.TOOLS:
            name = tool_def["name"]
            args = minimal_args(name, tool_def)
            client = RecordingClient()
            entry: dict = {
                "module": mod.__name__.rsplit(".", 1)[-1],
                "tool_sha256": tool_def_sha256(tool_def),
                "args": args,
            }
            try:
                await mod.handle(name, dict(args), client)
            except Exception as exc:  # recorded: upstream itself fails for these args
                entry["error"] = f"{type(exc).__name__}: {exc}"
            entry["calls"] = client.calls
            tools[name] = entry
    return tools


def main(argv: list[str]) -> int:
    """``[--check] [<commit>]``. --check compares instead of writing (exit 1 on a difference)."""
    check = "--check" in argv
    rest = [a for a in argv if a != "--check"]
    commit = rest[0] if rest else UPSTREAM_COMMIT
    with tempfile.TemporaryDirectory() as tmp:
        _extract(commit, Path(tmp))
        sys.path.insert(0, tmp)
        modules = [importlib.import_module(f"{PKG}.tools.{m}") for m in UPSTREAM_MODULES]
        tools = asyncio.run(_run_all(modules))
    doc = {
        "upstream": "ry-ops/proxmox-mcp-server@7276144",
        "repo_commit": commit,
        "tool_count": len(tools),
        "tools": tools,
    }
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    if check:
        same = OUT.exists() and OUT.read_text() == text
        print(f"{OUT.relative_to(ROOT)}: {'up to date' if same else 'DIFFERS'}", file=sys.stderr)
        return 0 if same else 1
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(tools)} tools", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
