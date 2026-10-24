"""H8: proxmox-mcp-selfcheck (offline checks, live least-privilege check, CLI contract)."""

import datetime as dt
import json
import os
import sys

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from proxmox_mcp import enrollment, selfcheck

TODAY = dt.date(2026, 10, 24)
SECRETS = {
    "alice": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
    "bob": "2c9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bee",
}


def put(d, name, text, mode=0o400):
    p = d / name
    if p.exists():
        os.chmod(p, 0o600)
    p.write_text(text)
    os.chmod(p, mode)
    return p


def pub_pem(key) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


@pytest.fixture
def broker(tmp_path, monkeypatch):
    creds = tmp_path / "creds"
    creds.mkdir(mode=0o700)
    logs = tmp_path / "logs"
    logs.mkdir()
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    monkeypatch.setenv("BROKER_CREDENTIALS_DIR", str(creds))
    env = {
        "PROXMOX_HOST": "pve.example.internal",
        "PROXMOX_TLS_FINGERPRINT": "ab" * 32,
        "BROKER_CREDENTIALS_DIR": str(creds),
        "CF_ACCESS_TEAM_DOMAIN": "https://team.cloudflareaccess.com",
        "CF_ACCESS_AUD": "a" * 64,
        "BROKER_ALLOWED_SERVICE_CLIENT_IDS": "abc123.access",
        "MCP_AUDIT_LOG": str(logs / "audit.jsonl"),
    }
    users = {
        "Alice@Example.com": {
            "mode": "operator",
            "proxmox_userid": "mcp-alice@pve",
            "token_credential": "pve-token-alice",
            "token_expires": "2027-01-31",
        },
        "bob@example.com": {
            "mode": "ro",
            "proxmox_userid": "mcp-bob@pve",
            "token_credential": "pve-token-bob",
            "token_expires": "2027-01-31",
        },
    }
    put(creds, "pve-token-alice", f"mcp-alice@pve!mcp={SECRETS['alice']}\n")
    put(creds, "pve-token-bob", f"mcp-bob@pve!mcp={SECRETS['bob']}\n")
    put(creds, "worker-identity.pub", pub_pem(ed25519.Ed25519PrivateKey.generate()))

    class B:
        pass

    b = B()
    b.creds, b.env, b.users, b.logs = creds, env, users, logs

    def write_enrollment(strip_expiry=True):
        # Until the enrollment.py patch lands, the broker's parser rejects token_expires,
        # so the "broker-valid" file omits it and expiry comes from the raw document.
        doc_users = {
            k: {kk: vv for kk, vv in v.items() if not (strip_expiry and kk == "token_expires")}
            for k, v in b.users.items()
        }
        put(creds, "enrollment.json", json.dumps({"users": doc_users}))
        enrollment._cache.clear()

    b.write_enrollment = write_enrollment
    write_enrollment()
    return b


def run(b, **kw):
    kw.setdefault("today", TODAY)
    return selfcheck.run_checks(environ=b.env, **kw)


def by_id(report, prefix):
    return [c for c in report["checks"] if c["id"].startswith(prefix)]


def test_clean_broker_only_warns_about_missing_expiry(broker):
    report = run(broker)
    fails = [c for c in report["checks"] if c["status"] == "fail"]
    assert fails == []
    assert {c["id"] for c in report["checks"] if c["status"] == "warn"} == {
        "token_expiry:alice@example.com",
        "token_expiry:bob@example.com",
    }
    assert report["status"] == "warn" and report["exit_code"] == selfcheck.EXIT_WARN
    assert by_id(report, "worker_key")[0]["status"] == "pass"
    assert by_id(report, "token:alice@example.com")[0]["details"]["token_id"] == "mcp-alice@pve!mcp"
    text = json.dumps(report)
    assert all(s not in text for s in SECRETS.values())


def test_token_expiry_rules():
    table = {
        "a": enrollment.Enrollment("a", "ro", "a@pve", "t-a"),
        "b": enrollment.Enrollment("b", "ro", "b@pve", "t-b"),
        "c": enrollment.Enrollment("c", "ro", "c@pve", "t-c"),
        "d": enrollment.Enrollment("d", "ro", "d@pve", "t-d"),
        "e": enrollment.Enrollment("e", "ro", "e@pve", "t-e"),
    }
    raw = {
        "a": {"token_expires": "2027-06-01"},
        "b": {"token_expires": "2026-11-07"},  # 14 days
        "c": {"token_expires": "2026-10-24"},  # today: expired
        "d": {"token_expires": "24/10/2027"},
        "e": {},
    }
    got = {c.id.split(":")[1]: c.status for c in selfcheck.check_token_expiry(table, raw, TODAY)}
    assert got == {"a": "pass", "b": "warn", "c": "fail", "d": "fail", "e": "warn"}


def test_expiry_from_enrollment_attribute_after_patch():
    """Once enrollment.Enrollment carries token_expires (patch E1), selfcheck uses it."""

    class Patched:
        mode, proxmox_userid, token_credential = "ro", "a@pve", "t"
        token_expires = dt.date(2026, 10, 1)

    checks = selfcheck.check_token_expiry({"a": Patched()}, {}, TODAY)
    assert checks[0].status == "fail"


def test_expiry_in_file_rejected_until_enrollment_patch(broker):
    broker.write_enrollment(strip_expiry=False)
    report = run(broker)
    status = by_id(report, "enrollment")[0]["status"]
    # Today the broker would refuse this file, and selfcheck says so; after patch E1 it passes.
    expected = (
        "pass"
        if "token_expires" in getattr(enrollment, "_ENTRY_KEYS", ())
        or hasattr(enrollment, "_OPTIONAL_KEYS")
        else "fail"
    )
    assert status == expected


def test_bad_config_stops_early(broker):
    broker.env["MCP_ALLOW_ADMIN_TOOL"] = "1"
    report = run(broker)
    assert [c["id"] for c in report["checks"]] == ["config"]
    assert report["exit_code"] == selfcheck.EXIT_FAIL
    assert any(
        "did you mean MCP_ALLOW_ADMIN_TOOLS" in p
        for p in report["checks"][0]["details"]["problems"]
    )


def test_dangerous_flags_are_warnings(broker):
    broker.env["MCP_ALLOW_ADMIN_TOOLS"] = "1"
    report = run(broker)
    flags = by_id(report, "dangerous_flags")
    assert [c["details"]["flag"] for c in flags] == ["MCP_ALLOW_ADMIN_TOOLS"]


def test_missing_enrollment_fails(broker):
    os.chmod(broker.creds / "enrollment.json", 0o600)
    (broker.creds / "enrollment.json").unlink()
    assert by_id(run(broker), "enrollment")[0]["status"] == "fail"


def test_unreadable_and_mismatched_tokens(broker):
    put(broker.creds, "pve-token-bob", f"someone@pve!mcp={SECRETS['bob']}\n")
    (broker.creds / "pve-token-alice").chmod(0o444)
    report = run(broker)
    alice = by_id(report, "token:alice@example.com")[0]
    bob = by_id(report, "token:bob@example.com")[0]
    if sys.platform != "win32":
        assert alice["status"] == "fail" and "other users" in alice["message"]
    assert bob["status"] == "fail" and "different Proxmox user" in bob["message"]
    assert SECRETS["bob"] not in json.dumps(report)


def test_shared_user_credential_or_secret_fails(broker):
    broker.users["bob@example.com"]["token_credential"] = "pve-token-alice"
    broker.users["bob@example.com"]["proxmox_userid"] = "mcp-alice@pve"
    broker.write_enrollment()
    # enrollment.py now refuses a shared key at load time (one person, one key), so the
    # whole file is invalid and selfcheck fails the enrollment check itself.
    (check,) = by_id(run(broker), "enrollment")
    assert check["status"] == "fail" and "invalid" in check["message"]


def test_pam_user_warns(broker):
    broker.users["bob@example.com"]["proxmox_userid"] = "mcp-bob@pam"
    put(broker.creds, "pve-token-bob", f"mcp-bob@pam!mcp={SECRETS['bob']}\n")
    broker.write_enrollment()
    bob = by_id(run(broker), "token:bob@example.com")[0]
    assert bob["status"] == "warn" and "@pam" in bob["message"]


def test_rw_requires_admin_flag(broker):
    broker.users["bob@example.com"]["mode"] = "rw"
    broker.write_enrollment()
    assert by_id(run(broker), "modes")[0]["status"] == "fail"
    broker.env["MCP_ALLOW_ADMIN_TOOLS"] = "1"
    modes = by_id(run(broker), "modes")[0]
    assert modes["status"] == "warn" and modes["details"]["subjects"] == ["bob@example.com"]


@pytest.mark.parametrize("kind", ["missing", "ecdsa", "private", "garbage"])
def test_worker_key(broker, kind):
    path = broker.creds / "worker-identity.pub"
    os.chmod(path, 0o600)
    if kind == "missing":
        path.unlink()
    elif kind == "ecdsa":
        put(broker.creds, "worker-identity.pub", pub_pem(ec.generate_private_key(ec.SECP256R1())))
    elif kind == "private":
        pem = (
            ed25519.Ed25519PrivateKey.generate()
            .private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            .decode()
        )
        put(broker.creds, "worker-identity.pub", pem)
    else:
        put(broker.creds, "worker-identity.pub", "not a key")
    report = run(broker)
    assert by_id(report, "worker_key")[0]["status"] == "fail"
    if kind == "private":
        assert by_id(report, "stray_private_key")[0]["status"] == "fail"
        assert "BEGIN PRIVATE" not in json.dumps(report)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_credentials_dir_modes(broker):
    broker.creds.chmod(0o755)
    assert by_id(run(broker), "credentials_dir")[0]["status"] == "warn"
    broker.creds.chmod(0o777)
    assert by_id(run(broker), "credentials_dir")[0]["status"] == "fail"
    broker.creds.chmod(0o700)


@pytest.mark.skipif(sys.platform == "win32" or os.geteuid() == 0, reason="root ignores modes")
def test_audit_path_not_writable(broker):
    broker.logs.chmod(0o500)
    try:
        check = by_id(run(broker), "audit_path")[0]
        assert check["status"] == "fail" and check["details"]["checked_as"]
    finally:
        broker.logs.chmod(0o700)


def test_audit_path_probe_leaves_nothing(broker):
    assert by_id(run(broker), "audit_path")[0]["status"] == "pass"
    assert list(broker.logs.iterdir()) == []
    (broker.logs / "audit.jsonl").write_text("line\n")
    assert by_id(run(broker), "audit_path")[0]["status"] == "pass"
    assert (broker.logs / "audit.jsonl").read_text() == "line\n"


# ---- privilege evaluation ---------------------------------------------------------------


def test_evaluate_permissions():
    ok = {"/pool/mcp": {"VM.Audit": 1, "Datastore.Audit": 1, "Sys.Audit": 0}, "/": {"Sys.Audit": 0}}
    assert selfcheck.evaluate_permissions(ok, "ro") == []
    assert selfcheck.evaluate_permissions({"/vms/100": {"VM.PowerMgmt": 1}}, "ro") == [
        "/vms/100: VM.PowerMgmt exceeds mode ro"
    ]
    assert selfcheck.evaluate_permissions({"/vms/100": {"VM.PowerMgmt": 1}}, "operator") == []
    bad = selfcheck.evaluate_permissions(
        {
            "/": {"Sys.Audit": 1, "Datastore.Allocate": 0},
            "/nodes/pve": {"Sys.Console": 0, "Realm.AllocateUser": 0, "Sys.Modify": 1},
            "/vms/1": {"VM.Console": 0, "VM.GuestAgent.Unrestricted": 0},
            "/access": {"Permissions.Modify": 0, "User.Modify": 0},
        },
        "rw",
    )
    joined = "\n".join(bad)
    for needle in (
        "propagates from /",
        "Datastore.Allocate on /",
        "Sys.Console is never",
        "Realm.AllocateUser is never",
        "Sys.Modify is never",
        "VM.Console is never",
        "VM.GuestAgent.Unrestricted is never",
        "Permissions.Modify is never",
        "User.Modify is never",
    ):
        assert needle in joined, needle
    assert selfcheck.evaluate_permissions({"/storage/x": {"Datastore.Allocate": 0}}, "rw") == []
    assert selfcheck.evaluate_permissions([], "ro") == ["unexpected /access/permissions response"]
    assert selfcheck.evaluate_permissions({"/x": {"VM.Audit": 1}}, "nonsense")


def test_allowed_sets_are_nested_and_disjoint_from_forbidden():
    a = selfcheck.ALLOWED_PRIVILEGES
    assert a["ro"] < a["operator"] < a["rw"]
    assert not (a["rw"] & selfcheck.ALWAYS_FORBIDDEN)


# ---- live -----------------------------------------------------------------------------------


def live_transport(perms_by_user, seen):
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("Authorization", "")
        seen.append((request.method, request.url.path, auth))
        user = auth.split("=", 1)[1].split("!", 1)[0] if "=" in auth else ""
        if user not in perms_by_user:
            return httpx.Response(401, json={"data": None})
        if request.url.path.endswith("/version"):
            return httpx.Response(200, json={"data": {"version": "8.2.4"}})
        if request.url.path.endswith("/access/permissions"):
            return httpx.Response(200, json={"data": perms_by_user[user]})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_live_pass_and_fail(broker):
    seen = []
    perms = {
        "mcp-alice@pve": {"/pool/mcp": {"VM.Audit": 1, "VM.PowerMgmt": 1, "VM.Snapshot": 1}},
        "mcp-bob@pve": {"/pool/mcp": {"VM.Audit": 1, "VM.PowerMgmt": 1}, "/": {"Sys.Audit": 1}},
    }
    report = run(broker, live=True, transport=live_transport(perms, seen))
    alice = by_id(report, "live:alice@example.com")[0]
    bob = by_id(report, "live:bob@example.com")[0]
    assert alice["status"] == "pass" and alice["details"]["proxmox_version"] == "8.2.4"
    assert bob["status"] == "fail"
    assert "/pool/mcp: VM.PowerMgmt exceeds mode ro" in bob["details"]["violations"]
    assert any("propagates from /" in v for v in bob["details"]["violations"])
    assert {(m, p) for m, p, _ in seen} == {
        ("GET", "/api2/json/version"),
        ("GET", "/api2/json/access/permissions"),
    }
    assert {a for *_, a in seen} == {
        f"PVEAPIToken=mcp-alice@pve!mcp={SECRETS['alice']}",
        f"PVEAPIToken=mcp-bob@pve!mcp={SECRETS['bob']}",
    }
    assert all(s not in json.dumps(report) for s in SECRETS.values())


def test_live_rejected_token(broker):
    report = run(broker, live=True, transport=live_transport({}, []))
    live = by_id(report, "live:")
    assert {c["status"] for c in live} == {"fail"}
    assert all("token rejected" in c["message"] for c in live)


def test_live_never_follows_redirects(broker):
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(302, headers={"Location": "https://evil.example.com/"})

    report = run(broker, live=True, transport=httpx.MockTransport(handler))
    assert {c["status"] for c in by_id(report, "live:")} == {"fail"}
    assert set(seen) == {"pve.example.internal"}


# ---- CLI ------------------------------------------------------------------------------------


def test_cli_json_and_exit_codes(broker, monkeypatch, capsys):
    for k in list(os.environ):
        if k.startswith(("PROXMOX_", "MCP_", "BROKER_", "CF_ACCESS_")):
            monkeypatch.delenv(k)
    for k, v in broker.env.items():
        monkeypatch.setenv(k, v)
    assert selfcheck.main([]) == selfcheck.EXIT_WARN
    out = json.loads(capsys.readouterr().out)
    assert out["tool"] == "proxmox-mcp-selfcheck" and out["status"] == "warn"
    monkeypatch.setenv("PROXMOX_PASSWORD", "hunter2-secret")
    assert selfcheck.main([]) == selfcheck.EXIT_FAIL
    assert "hunter2-secret" not in capsys.readouterr().out
    with pytest.raises(SystemExit) as ei:
        selfcheck.main(["--bogus"])
    assert ei.value.code == selfcheck.EXIT_USAGE


def test_cli_crash_is_json(monkeypatch, capsys):
    def boom(**_):
        raise RuntimeError("secret-detail")

    monkeypatch.setattr(selfcheck, "run_checks", boom)
    assert selfcheck.main([]) == selfcheck.EXIT_CRASH
    out = capsys.readouterr().out
    assert json.loads(out)["error"] == "RuntimeError" and "secret-detail" not in out


def test_script_entry_point_declared():
    from pathlib import Path

    text = (Path(__file__).parents[1] / "pyproject.toml").read_text()
    assert 'proxmox-mcp-selfcheck = "proxmox_mcp.selfcheck:main"' in text
