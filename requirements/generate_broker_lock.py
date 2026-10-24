"""Generate requirements/broker-win.txt: the hashed, wheel-only runtime lock for the broker.

Source of truth is uv.lock. This script only narrows it: the runtime dependency set
(no dev group, no project) as uv resolves it, evaluated for CPython 3.14 on the two
supported targets, with one --hash per wheel that can install on either target:

  * win_amd64           (the Windows Server 2025 broker)
  * manylinux x86_64    (Linux dev hosts and CI)

sdists are never listed, and the file starts with `--only-binary :all:`, so an install
cannot fall back to building from source (a build runs arbitrary code from the sdist).

Install (the Windows installer does exactly this):

  pip install --require-hashes --no-deps -r requirements/broker-win.txt
  pip install --no-deps proxmox_mcp_server-<version>-py3-none-any.whl

Regenerate after `uv lock`:   python requirements/generate_broker_lock.py
CI drift check:               python requirements/generate_broker_lock.py --check

Needs Python >= 3.11 (tomllib), `packaging`, and `uv` on PATH.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import tomllib
from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.tags import Tag, compatible_tags, cpython_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "uv.lock"
OUT = ROOT / "requirements" / "broker-win.txt"

PY = (3, 14)
PY_FULL = "3.14.6"

_COMMON_ENV = {
    "python_version": "3.14",
    "python_full_version": PY_FULL,
    "implementation_name": "cpython",
    "implementation_version": PY_FULL,
    "platform_python_implementation": "CPython",
    "platform_release": "",
    "platform_version": "",
    "extra": "",
}

# glibc 2.17 (manylinux2014) through 2.39 (Ubuntu 24.04), newest first.
_LINUX_PLATFORMS = [f"manylinux_2_{minor}_x86_64" for minor in range(39, 4, -1)] + [
    "manylinux2014_x86_64",
    "manylinux2010_x86_64",
    "manylinux1_x86_64",
]

TARGETS: dict[str, tuple[dict[str, str], str, set[Tag]]] = {}


def _tags(platforms: list[str]) -> set[Tag]:
    tags = set(cpython_tags(PY, abis=["cp314", "abi3", "none"], platforms=platforms))
    tags |= set(compatible_tags(PY, "cp314", platforms))
    return tags


TARGETS["win_amd64"] = (
    {
        **_COMMON_ENV,
        "sys_platform": "win32",
        "platform_system": "Windows",
        "os_name": "nt",
        "platform_machine": "AMD64",
    },
    "sys_platform == 'win32'",
    _tags(["win_amd64"]),
)
TARGETS["manylinux_x86_64"] = (
    {
        **_COMMON_ENV,
        "sys_platform": "linux",
        "platform_system": "Linux",
        "os_name": "posix",
        "platform_machine": "x86_64",
    },
    "sys_platform == 'linux'",
    _tags(_LINUX_PLATFORMS),
)


def _runtime_requirements() -> list[Requirement]:
    uv = shutil.which("uv")
    if uv is None:
        sys.exit("uv is required (https://docs.astral.sh/uv/)")
    # Fixed argv, no shell; `uv export --frozen` reads uv.lock and never resolves.
    out = subprocess.run(  # noqa: S603
        [
            uv,
            "export",
            "--frozen",
            "--no-dev",
            "--no-emit-project",
            "--no-hashes",
            "--no-header",
            "--no-annotate",
            "--quiet",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [Requirement(line) for line in out.splitlines() if line and not line.startswith("#")]


def _lock_index() -> dict[tuple[str, str], list[dict]]:
    data = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    return {
        (canonicalize_name(pkg["name"]), pkg["version"]): pkg.get("wheels", [])
        for pkg in data["package"]
        if "version" in pkg
    }


def render() -> str:
    index = _lock_index()
    blocks: list[str] = []
    for req in sorted(_runtime_requirements(), key=lambda r: canonicalize_name(r.name)):
        (spec,) = req.specifier
        version = spec.version
        targets = [
            name
            for name, (env, _, _) in TARGETS.items()
            if req.marker is None or Marker(str(req.marker)).evaluate(env)
        ]
        if not targets:
            continue
        hashes: set[str] = set()
        for name in targets:
            _, _, supported = TARGETS[name]
            found = False
            for wheel in index[(canonicalize_name(req.name), version)]:
                filename = wheel["url"].rsplit("/", 1)[-1]
                if parse_wheel_filename(filename)[3] & supported:
                    hashes.add(wheel["hash"])
                    found = True
            if not found:
                sys.exit(f"{req.name}=={version}: no wheel for {name}; refusing an sdist")
        marker = "" if len(targets) == len(TARGETS) else f" ; {TARGETS[targets[0]][1]}"
        lines = [f"{canonicalize_name(req.name)}=={version}{marker}"]
        lines += [f"    --hash={h}" for h in sorted(hashes)]
        blocks.append(" \\\n".join(lines))
    header = (
        "# GENERATED by requirements/generate_broker_lock.py from uv.lock. Do not edit.\n"
        "# Broker runtime lock: CPython 3.14 on win_amd64 and manylinux x86_64, wheels only.\n"
        "#   pip install --require-hashes --no-deps -r requirements/broker-win.txt\n"
        "--only-binary :all:\n\n"
    )
    return header + "\n".join(blocks) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if the file is stale")
    args = parser.parse_args()
    text = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT.relative_to(ROOT)} is stale: run requirements/generate_broker_lock.py")
            return 1
        print(f"{OUT.relative_to(ROOT)} matches uv.lock")
        return 0
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
