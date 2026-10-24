"""Every registered tool, executed through the real broker as ro, operator and rw.

For each (tool, mode) the Worker-style request goes through the whole broker
(Access service token, Ed25519 identity assertion, enrollment, policy, schema,
handler, per-user token, outbound policy, output, audit) to a recording mock of
the Proxmox API. MCP_ALLOW_ADMIN_TOOLS=1, so rw reaches the admin tier.

Checked per case:
  * the decision matches the policy tier (ro: read; operator: read + operate;
    rw: read + operate + admin; forbidden: nobody);
  * a denied call never reaches Proxmox and writes exactly one audit line (in, denied);
  * an allowed call reaches Proxmox only with the CALLER'S API token, with the
    same methods, paths and parameters as the upstream handler at a63576c
    (tests/fixtures/upstream_calls.json), writes one audit line per side
    (in allowed, out ok) plus one "proxmox" line per API request, and returns a
    labelled, redacted result;
  * no API token secret, canary secret or canary PHI value appears in a result
    or in the audit log;
  * the tier agrees with the traffic: a read tool only sends GET, and a tool
    that sends DELETE is admin.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fixtures.broker import MODES, RAY, SERVICE_CLIENT_ID, USERS, audit_lines, running_broker
from fixtures.mock_proxmox import CANARY_PHI, CANARY_SECRET
from fixtures.tool_args import minimal_args

from proxmox_mcp import audit, policy, router
from proxmox_mcp.output import OPEN_TAG, UNTRUSTED_LABEL

UPSTREAM = json.loads((Path(__file__).parent / "fixtures" / "upstream_calls.json").read_text())
TIERS_FOR = {"ro": {"read"}, "operator": {"read", "operate"}, "rw": {"read", "operate", "admin"}}

# Deliberate differences from the upstream handler, each with its reason.
UPSTREAM_DELTAS: dict[str, tuple[list, str]] = {
    "analyze_schedule": (
        [["GET", "/cluster/jobs/schedule-analyze", [["schedule", "daily"]]]],
        "PVE defines schedule-analyze as GET; upstream sent POST, which PVE rejects",
    ),
}

CASES = [(tool, mode) for tool in sorted(router.REGISTRY) for mode in MODES]


@pytest.fixture(scope="module")
def broker(tmp_path_factory):
    with running_broker(tmp_path_factory.mktemp("e2e-matrix")) as b:
        yield b


@pytest.fixture
def b(broker):
    broker.proxmox.reset()
    return broker


def _expected_calls(tool: str) -> list:
    if tool in UPSTREAM_DELTAS:
        return UPSTREAM_DELTAS[tool][0]
    return UPSTREAM["tools"][tool]["calls"]


@pytest.mark.parametrize("tool,mode", CASES)
def test_tool_matrix(b, tool, mode):
    user = USERS[mode]
    tier = policy.tool_tier(tool)
    expect_allowed = tier in TIERS_FOR[mode]
    args = minimal_args(tool, router.REGISTRY[tool][0])

    r = b.worker.execute(user.email, tool, args)
    assert r.status_code == 200
    body = r.json()
    text = body["text"]
    seen = list(b.proxmox.requests)
    lines = audit_lines()
    tool_lines = [x for x in lines if x.get("target") == tool]
    pve_lines = [x for x in lines if x.get("event") == "proxmox"]
    audit_text = Path(audit.configured_path()).read_text()

    for u in USERS.values():
        assert u.secret not in text and u.secret not in audit_text
    assert CANARY_SECRET not in text and CANARY_PHI not in text

    if not expect_allowed:
        assert body["ok"] is False, f"{tool} ({tier}) ran for {mode}"
        assert "blocked by policy" in text
        assert seen == [], f"{tool} reached Proxmox for {mode}"
        assert [(x["side"], x["status"]) for x in tool_lines] == [("in", "denied")]
        assert tool_lines[0]["user"] == user.email
        assert pve_lines == []
        return

    assert body["ok"] is True, f"{tool} as {mode}: {text}"
    nonce = re.search(r"</untrusted-data-([0-9a-f]{32})>\Z", text)
    assert nonce, "result must end with the nonce close tag"
    n = nonce.group(1)
    assert text.startswith(UNTRUSTED_LABEL.format(nonce=n)) and OPEN_TAG.format(nonce=n) in text
    assert seen, f"{tool} made no Proxmox call"
    assert {s.authorization for s in seen} == {user.authorization}

    assert [(x["side"], x["status"]) for x in tool_lines] == [("in", "allowed"), ("out", "ok")]
    for x in tool_lines:
        assert x["user"] == user.email
        assert x["svc"] == SERVICE_CLIENT_ID and x["jti"] and x["ray"] == RAY
    # Every mutation is on record (write-ahead "attempt") before it is sent, and every
    # Proxmox line carries the request correlation (jti, svc) of the call that caused it.
    attempts = [x for x in pve_lines if x["status"] == "attempt"]
    done = [x for x in pve_lines if x["status"] != "attempt"]
    assert [(x["method"], x["path"]) for x in attempts] == [
        (r.method, r.path) for r in seen if r.method != "GET"
    ]
    for line in pve_lines:
        assert line["kind"] == "user" and line["jti"] and line["svc"] == SERVICE_CLIENT_ID
    for line, req in zip(done, seen, strict=True):
        assert (line["user"], line["token_id"], line["mode"]) == (user.email, user.token_id, mode)
        assert (line["method"], line["path"], line["status"]) == (req.method, req.path, 200)
    assert audit.verify_chain(audit.configured_path()) == 0

    assert [s.call() for s in seen] == _expected_calls(tool)

    methods = {s.method for s in seen}
    if tier == "read":
        assert methods == {"GET"}, f"read tool {tool} sent {methods}"
    if "DELETE" in methods:
        assert tier == "admin"


def test_every_tool_is_in_the_matrix():
    assert {t for t, _ in CASES} == set(router.REGISTRY)
    assert len(CASES) == 3 * len(router.REGISTRY)
