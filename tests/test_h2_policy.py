"""H2 red team: tier re-audit, catalog shape, STD-02 meta-tool conformance, enrollment."""

from __future__ import annotations

import json
import os
import threading

import pytest

from proxmox_mcp import enrollment, policy, router
from proxmox_mcp.identity import Identity, current_identity
from proxmox_mcp.router import RouterError, handle_meta


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in ("MCP_ALLOW_ADMIN_TOOLS", "MCP_TOOL_DENY", "MCP_TOOL_ALLOW", "MCP_ENROLLMENT_FILE",
                "CREDENTIALS_DIRECTORY", "BROKER_CREDENTIALS_DIR", "MCP_LOCAL_MODE"):
        monkeypatch.delenv(var, raising=False)


# ----------------------------------------------------------------------------- tiers


# Bulk host logs and per-connection firewall logs: raw, unfiltered, host-wide (not scoped by
# the caller's pool ACL), and they carry HIPAA identifiers (client IP addresses, user names).
# Minimum necessary: not for read-only users; a rw admin may pull them deliberately.
ADMIN_ONLY_READS = ["get_node_syslog", "get_node_journal", "get_vm_firewall_log",
                    "get_node_firewall_log", "get_cluster_firewall_log"]


@pytest.mark.parametrize("name", ADMIN_ONLY_READS)
def test_raw_logs_are_admin(name):
    assert policy.tool_tier(name) == "admin"


@pytest.mark.parametrize("name", ["get_node_report", "list_webhook_endpoints"])
def test_bulk_dumps_and_secret_bearing_lists_are_forbidden(name):
    # pvereport runs as root and dumps every guest config, firewall and corosync config
    # regardless of the token's ACL; webhook URLs/headers are commonly the secret itself.
    assert policy.tool_tier(name) == "forbidden"
    assert policy.FORBIDDEN_RE.search(name)


def test_task_and_cluster_logs_stay_read():
    # Task logs are written by PVE workers (no guest-agent command output: agent exec is
    # not a task) and are scoped by Proxmox ACL; the cluster log is task start/stop events.
    for name in ("get_task_log", "get_task_status", "get_cluster_log", "list_node_tasks"):
        assert policy.tool_tier(name) == "read"


def test_ro_and_operator_cannot_reach_raw_logs():
    for mode in ("ro", "operator"):
        names = {e["name"] for e in policy.catalog_for(mode)}
        assert not names & set(ADMIN_ONLY_READS + ["get_node_report", "list_webhook_endpoints"])


def test_tier_counts_are_reported():
    counts: dict[str, int] = {}
    for name in router.REGISTRY:
        counts[policy.tool_tier(name)] = counts.get(policy.tool_tier(name), 0) + 1
    assert sum(counts.values()) == len(router.REGISTRY)
    assert set(counts) == {"read", "operate", "admin", "forbidden"}


# ----------------------------------------------------------------------------- catalog


def test_catalog_entries_carry_category():
    for entry in policy.catalog_for("ro"):
        assert entry["category"] == router.REGISTRY[entry["name"]][1].__name__.rsplit(".", 1)[-1]
    cats = {e["category"] for e in policy.catalog_for("ro")}
    assert {"qemu", "lxc", "nodes", "storage"} <= cats


def test_catalog_version_covers_category(monkeypatch):
    before = policy.catalog_version("ro")
    tool_def, mod = router.REGISTRY["list_vms"]

    class Fake:
        __name__ = "proxmox_mcp.tools.renamed"

    monkeypatch.setitem(router.REGISTRY, "list_vms", (tool_def, Fake))
    assert policy.catalog_version("ro") != before


# ----------------------------------------------------------------------------- STD-02


class _Exec:
    def __init__(self):
        self.calls = []

    async def __call__(self, tool, arguments):
        self.calls.append((tool, arguments))
        return "ok"


@pytest.fixture
def as_local():
    token = current_identity.set(Identity(subject="local", kind="local"))
    yield
    current_identity.reset(token)


async def test_hidden_tools_never_surface_in_any_search(as_local, monkeypatch):
    for mode in ("ro", "operator", "rw"):
        monkeypatch.setenv("MCP_LOCAL_MODE", mode)
        visible = {d["name"] for d in router.visible_tools(Identity(subject="local", kind="local"))}
        for name in router.REGISTRY:
            if name in visible:
                continue
            out = await handle_meta("list_tools", {"search_terms": [name]}, _Exec())
            assert f'"{name}"' not in out


async def test_summary_hides_forbidden_examples(as_local, monkeypatch):
    monkeypatch.setenv("MCP_LOCAL_MODE", "rw")
    monkeypatch.setenv("MCP_ALLOW_ADMIN_TOOLS", "1")
    text = await handle_meta("list_tools", {}, _Exec())
    for name in router.REGISTRY:
        if policy.tool_tier(name) == "forbidden":
            assert f'"{name}"' not in text


async def test_describe_probe_of_hidden_equals_unknown_in_batch(as_local):
    a = await handle_meta("describe_tool_input", {"tool_names": ["list_vms", "vm_agent_exec"]}, _Exec())
    b = await handle_meta("describe_tool_input", {"tool_names": ["list_vms", "vm_agent_exex"]}, _Exec())
    assert a.replace("vm_agent_exec", "X") == b.replace("vm_agent_exex", "X")


async def test_search_terms_whitespace_only_is_a_summary(as_local):
    out = json.loads(await handle_meta("list_tools", {"search_terms": ["  "]}, _Exec()))
    assert "categories" in out


async def test_tool_name_with_newline_is_invalid_input(as_local):
    with pytest.raises(RouterError, match="Invalid input for tool execute_tool"):
        await handle_meta("execute_tool", {"name": "list_vms\n", "arguments": {}}, _Exec())
    with pytest.raises(RouterError, match="Invalid input for tool describe_tool_input"):
        await handle_meta("describe_tool_input", {"tool_names": ["list_vms\n"]}, _Exec())


async def test_execute_error_texts_follow_std02(as_local):
    with pytest.raises(RouterError, match=r"^Unknown tool: nope$"):
        await handle_meta("execute_tool", {"name": "nope", "arguments": {}}, _Exec())
    with pytest.raises(RouterError, match=r"^Invalid input for tool get_vm_status: "):
        await handle_meta("execute_tool", {"name": "get_vm_status", "arguments": {}}, _Exec())


def test_meta_annotations_std02():
    tools = {t.name: t for t in router.meta_tools()}
    for name in ("list_tools", "describe_tool_input"):
        a = tools[name].annotations
        assert a.readOnlyHint is True and a.idempotentHint is True and a.destructiveHint is False
    a = tools["execute_tool"].annotations
    assert a.readOnlyHint is False and a.destructiveHint is True and a.openWorldHint is True


# ----------------------------------------------------------------------------- enrollment


def _entry(mode="ro", userid="kate@pve", cred="pve-token-kate"):
    return {"mode": mode, "proxmox_userid": userid, "token_credential": cred}


def _write(path, doc):
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def _user(email):
    return Identity(subject=email, kind="user", email=email)


@pytest.mark.parametrize("email", [
    "Kate@example.com",  # KELVIN SIGN lowercases to ASCII "k"
    "KATE@EXAMPLE.COṀ",
    "kate＠example.com",  # fullwidth @
    "kate@example.com\n",
    " kate@example.com",
    "kate@examplе.com",  # Cyrillic e
])
def test_identity_unicode_confusables_do_not_match(tmp_path, monkeypatch, email):
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", _write(tmp_path / "e.json", {"users": {"kate@example.com": _entry()}}))
    assert enrollment.enrollment_for(_user("kate@example.com")).mode == "ro"
    assert enrollment.enrollment_for(_user("Kate@Example.com")).mode == "ro"
    with pytest.raises(PermissionError):
        enrollment.enrollment_for(_user(email))


@pytest.mark.parametrize("key", ["Kate@example.com", "İnfo@example.com", "info@exımple.com"])
def test_enrollment_file_non_ascii_emails_rejected(tmp_path, key):
    with pytest.raises(enrollment.EnrollmentError):
        enrollment.load_enrollments(_write(tmp_path / "e.json", {"users": {key: _entry()}}))


def test_symlinked_enrollment_file_refused(tmp_path, monkeypatch):
    real = _write(tmp_path / "real.json", {"users": {"kate@example.com": _entry()}})
    link = tmp_path / "enrollment.json"
    os.symlink(real, link)
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", str(link))
    with pytest.raises(PermissionError):
        enrollment.enrollment_for(_user("kate@example.com"))


def test_non_regular_enrollment_file_refused(tmp_path, monkeypatch):
    d = tmp_path / "dir.json"
    d.mkdir()
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", str(d))
    with pytest.raises(PermissionError):
        enrollment.enrollment_for(_user("kate@example.com"))


def test_oversize_enrollment_file_refused_without_reading_it_all(tmp_path):
    path = tmp_path / "e.json"
    path.write_bytes(b" " * (enrollment.MAX_FILE_BYTES + 1))
    with pytest.raises(enrollment.EnrollmentError, match="larger than"):
        enrollment.load_enrollments(str(path))


def test_same_size_same_mtime_revocation_is_seen(tmp_path):
    # rw -> ro has the same length; restore mtime and keep the inode: a stat-keyed cache
    # would keep serving rw (a missed revocation).
    path = tmp_path / "e.json"
    _write(path, {"users": {"kate@example.com": _entry("rw")}})
    st = os.stat(path)
    assert enrollment.load_enrollments(str(path))["kate@example.com"].mode == "rw"
    with open(path, "r+", encoding="utf-8") as fh:
        text = fh.read().replace('"rw"', '"ro"')
        fh.seek(0)
        fh.write(text)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))
    assert os.stat(path).st_size == st.st_size
    assert enrollment.load_enrollments(str(path))["kate@example.com"].mode == "ro"


def test_concurrent_reloads_never_grant_more_than_the_file(tmp_path):
    path = tmp_path / "e.json"
    docs = [{"users": {"kate@example.com": _entry("ro")}},
            {"users": {"kate@example.com": _entry("ro"), "bob@example.com": _entry("ro", "bob@pve", "t-bob")}}]
    _write(path, docs[0])
    errors = []
    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            tmp = tmp_path / f"t{i % 2}.json"
            _write(tmp, docs[i % 2])
            os.replace(tmp, path)
            i += 1

    def reader():
        for _ in range(300):
            try:
                table = enrollment.load_enrollments(str(path))
            except enrollment.EnrollmentError:
                continue
            if any(e.mode != "ro" for e in table.values()):
                errors.append("escalated")

    t = threading.Thread(target=writer)
    t.start()
    readers = [threading.Thread(target=reader) for _ in range(4)]
    for r in readers:
        r.start()
    for r in readers:
        r.join()
    stop.set()
    t.join()
    assert errors == []


# ----------------------------------------------------------------------------- one person, one key


@pytest.mark.parametrize("doc", [
    # two users, same token credential
    {"users": {"a@example.com": _entry("ro", "a@pve", "pve-token-x"),
               "b@example.com": _entry("ro", "b@pve", "pve-token-x")}},
    # same credential, differing only in case (case-insensitive credential stores)
    {"users": {"a@example.com": _entry("ro", "a@pve", "pve-token-x"),
               "b@example.com": _entry("ro", "b@pve", "PVE-TOKEN-X")}},
    # user and service, same credential
    {"users": {"a@example.com": _entry("ro", "a@pve", "pve-token-x")},
     "services": {"svc1": _entry("ro", "svc@pve", "pve-token-x")}},
    # two users, same proxmox user
    {"users": {"a@example.com": _entry("ro", "shared@pve", "pve-token-a"),
               "b@example.com": _entry("rw", "shared@pve", "pve-token-b")}},
    # user and service, same proxmox user (case-insensitive)
    {"users": {"a@example.com": _entry("ro", "Shared@pve", "pve-token-a")},
     "services": {"svc1": _entry("ro", "shared@pve", "pve-token-b")}},
])
def test_shared_credential_or_userid_invalidates_file(tmp_path, monkeypatch, doc):
    path = _write(tmp_path / "e.json", doc)
    with pytest.raises(enrollment.EnrollmentError, match="share"):
        enrollment.load_enrollments(path)
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", path)
    with pytest.raises(PermissionError):  # everyone denied, including the first subject
        enrollment.enrollment_for(_user("a@example.com"))


def test_distinct_credentials_and_userids_accepted(tmp_path):
    doc = {"users": {"a@example.com": _entry("ro", "a@pve", "pve-token-a"),
                     "b@example.com": _entry("rw", "b@pve", "pve-token-b")},
           "services": {"svc1": _entry("ro", "svc@pve", "pve-token-svc")}}
    assert len(enrollment.load_enrollments(_write(tmp_path / "e.json", doc))) == 3
