"""H8: central fail-closed configuration (config.py)."""

import logging
import pickle
import re
from pathlib import Path

import pytest

from proxmox_mcp import config

PIN = "AB:" * 31 + "AB"
AUD = "a" * 64


def broker_env(tmp_path, **extra):
    env = {
        "PROXMOX_HOST": "pve.example.internal",
        "PROXMOX_TLS_FINGERPRINT": PIN,
        "BROKER_CREDENTIALS_DIR": str(tmp_path),
        "CF_ACCESS_TEAM_DOMAIN": "https://team.cloudflareaccess.com",
        "CF_ACCESS_AUD": AUD,
        "BROKER_ALLOWED_SERVICE_CLIENT_IDS": "abc123.access",
    }
    env.update(extra)
    return {k: v for k, v in env.items() if v is not None}


def stdio_env(**extra):
    env = {
        "PROXMOX_HOST": "192.0.2.10",
        "PROXMOX_USER": "dev@pve",
        "PROXMOX_TOKEN_NAME": "cli",
        "PROXMOX_TOKEN_VALUE": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
    }
    env.update(extra)
    return {k: v for k, v in env.items() if v is not None}


def problems(env, role="broker"):
    with pytest.raises(config.ConfigError) as ei:
        config.load(env, role=role)
    return ei.value.problems


def test_valid_broker_defaults_are_safe(tmp_path):
    s = config.load(broker_env(tmp_path), role="broker")
    assert s.bind == "127.0.0.1" and s.port == 8765
    assert s.require_access_jwt and not s.allow_admin_tools and not s.proxmox_insecure_tls
    assert s.proxmox_tls_fingerprints == ("ab" * 32,)
    assert s.tls_mode == "pinned"
    assert s.enrollment_file == str(tmp_path / "enrollment.json")
    assert s.cf_access_team_domain == "https://team.cloudflareaccess.com"
    assert s.dangerous_flags() == ()
    assert "127.0.0.1:8765" in s.allowed_hosts
    with pytest.raises(AttributeError):
        s.port = 1  # frozen


def test_unknown_variable_is_fatal_with_hint(tmp_path):
    found = problems(broker_env(tmp_path, MCP_ALOW_ADMIN_TOOLS="1"))
    assert any("MCP_ALOW_ADMIN_TOOLS" in p and "MCP_ALLOW_ADMIN_TOOLS" in p for p in found)
    found = problems(broker_env(tmp_path, CF_ACCESS_AUDIENCE=AUD, BROKER_FOO="x"))
    assert sum("unknown variable" in p for p in found) == 2


@pytest.mark.parametrize("name", ["PROXMOX_PASSWORD", "PROXMOX_VERIFY_SSL", "MCP_SERVER_TYPE"])
def test_removed_variables_are_fatal(tmp_path, name):
    assert any(p.startswith(name) for p in problems(broker_env(tmp_path, **{name: "x"})))


def test_unrelated_variables_are_ignored(tmp_path):
    config.load(broker_env(tmp_path, PATH="/usr/bin", LOG_LEVEL="INFO"), role="broker")


def test_mcp_client_injected_variables_are_ignored(tmp_path):
    """Claude Code / Desktop set these in the environment of servers they spawn."""
    env = {"MCP_TOOL_TIMEOUT": "60000", "MCP_CONNECTION_NONBLOCKING": "true", "MCP_TIMEOUT": "1"}
    config.load(stdio_env(**env), role="stdio")
    config.load(broker_env(tmp_path, **env), role="broker")
    assert any(
        "MCP_TOOL_TIMEOUTS" in p for p in problems(broker_env(tmp_path, MCP_TOOL_TIMEOUTS="1"))
    )


@pytest.mark.parametrize("value", ["true", "yes", "TRUE", "2", "1 ", " 1", "1\r", "on", "-1"])
def test_bools_must_be_exactly_0_or_1(tmp_path, value):
    found = problems(broker_env(tmp_path, PROXMOX_READ_ONLY=value))
    assert any("PROXMOX_READ_ONLY" in p for p in found)


def test_bool_0_1_and_empty(tmp_path):
    assert config.load(broker_env(tmp_path, PROXMOX_READ_ONLY="1")).proxmox_read_only
    assert not config.load(broker_env(tmp_path, PROXMOX_READ_ONLY="0")).proxmox_read_only
    assert not config.load(broker_env(tmp_path, PROXMOX_READ_ONLY="")).proxmox_read_only


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("PROXMOX_PORT", "0"),
        ("PROXMOX_PORT", "65536"),
        ("PROXMOX_PORT", "80a"),
        ("MCP_PORT", "-1"),
        ("MCP_RATE_PER_MIN", "0"),
        ("MCP_RATE_PER_DAY", "99999999999"),
        ("MCP_MAX_REQUEST_BYTES", "10"),
        ("MCP_MAX_RESULT_BYTES", str(10**12)),
        ("PROXMOX_TIMEOUT", "0x10"),
        ("MCP_MAX_CONCURRENCY", "1e3"),
    ],
)
def test_ints_are_bounded(tmp_path, name, value):
    assert any(name in p for p in problems(broker_env(tmp_path, **{name: value})))


@pytest.mark.parametrize(
    "host",
    [
        "https://pve",
        "pve:8006",
        "pve/api",
        "-pve",
        "pve..lan",
        "300.1.1.1",
        "a" * 254,
        "pve_1",
        "[::1]",
    ],
)
def test_proxmox_host_validated(tmp_path, host):
    assert any("PROXMOX_HOST" in p for p in problems(broker_env(tmp_path, PROXMOX_HOST=host)))


@pytest.mark.parametrize("host", ["pve", "pve.example.internal", "192.0.2.10", "2001:db8::1"])
def test_proxmox_host_accepted(tmp_path, host):
    assert config.load(broker_env(tmp_path, PROXMOX_HOST=host)).proxmox_host == host


@pytest.mark.parametrize(
    "url",
    [
        "http://team.cloudflareaccess.com",
        "team.cloudflareaccess.com",
        "https://team.cloudflareaccess.com/path",
        "https://user@team.cloudflareaccess.com",
        "https://team.cloudflareaccess.com:8443",
        "https://team.cloudflareaccess.com?x=1",
        "https://",
    ],
)
def test_team_domain_must_be_https_origin(tmp_path, url):
    found = problems(broker_env(tmp_path, CF_ACCESS_TEAM_DOMAIN=url))
    assert any("CF_ACCESS_TEAM_DOMAIN" in p for p in found)


def test_access_settings_required_unless_disabled(tmp_path):
    env = broker_env(
        tmp_path,
        CF_ACCESS_TEAM_DOMAIN=None,
        CF_ACCESS_AUD=None,
        BROKER_ALLOWED_SERVICE_CLIENT_IDS=None,
    )
    assert len([p for p in problems(env) if "required while" in p]) == 3
    s = config.load({**env, "BROKER_REQUIRE_ACCESS_JWT": "0"})
    assert s.dangerous_flags() == ("BROKER_REQUIRE_ACCESS_JWT=0",)


def test_broker_refuses_token_material_in_env(tmp_path):
    found = problems(broker_env(tmp_path, PROXMOX_TOKEN_VALUE="secret-value", PROXMOX_USER="a@pve"))
    assert any("PROXMOX_TOKEN_VALUE must not be set on the broker" in p for p in found)
    assert any("PROXMOX_USER must not be set" in p for p in found)
    assert all("secret-value" not in p for p in found)


def test_broker_refuses_insecure_tls_without_pin(tmp_path):
    env = broker_env(tmp_path, PROXMOX_TLS_FINGERPRINT=None, PROXMOX_INSECURE_TLS="1")
    assert any("PROXMOX_INSECURE_TLS" in p for p in problems(env))
    s = config.load(broker_env(tmp_path, PROXMOX_INSECURE_TLS="1"))
    assert "PROXMOX_INSECURE_TLS" in s.dangerous_flags()
    # stdio (developer) may run insecure, loudly
    assert config.load(stdio_env(PROXMOX_INSECURE_TLS="1"), role="stdio").tls_mode == "insecure"


def test_non_loopback_bind(tmp_path):
    assert any("MCP_BIND" in p for p in problems(broker_env(tmp_path, MCP_BIND="0.0.0.0")))
    assert any("MCP_BIND" in p for p in problems(broker_env(tmp_path, MCP_BIND="broker.lan")))
    s = config.load(broker_env(tmp_path, MCP_BIND="0.0.0.0", MCP_ALLOW_NON_LOOPBACK="1"))
    assert s.dangerous_flags() == ("MCP_ALLOW_NON_LOOPBACK",)
    assert config.load(broker_env(tmp_path, MCP_BIND="::1")).bind == "::1"


def test_paths_must_be_absolute(tmp_path):
    for name in ("MCP_AUDIT_LOG", "MCP_ENROLLMENT_FILE", "BROKER_DPAPI_ENTROPY_FILE"):
        assert any(name in p for p in problems(broker_env(tmp_path, **{name: "rel/x"})))
    assert any(
        "BROKER_CREDENTIALS_DIR" in p
        for p in problems(broker_env(tmp_path, BROKER_CREDENTIALS_DIR="c"))
    )
    s = config.load(
        broker_env(tmp_path, MCP_AUDIT_LOG=r"C:\ProgramData\ProxmoxMCP\logs\audit.jsonl")
    )
    assert s.audit_log.endswith("audit.jsonl")


def test_conflicting_credential_dirs(tmp_path):
    other = tmp_path / "other"
    found = problems(broker_env(tmp_path, CREDENTIALS_DIRECTORY=str(other)))
    assert any("different directories" in p for p in found)
    s = config.load(broker_env(tmp_path, CREDENTIALS_DIRECTORY=str(tmp_path)))
    assert s.credentials_dir == str(tmp_path)


def test_broker_requires_credentials_dir(tmp_path):
    assert any(
        "BROKER_CREDENTIALS_DIR" in p
        for p in problems(broker_env(tmp_path, BROKER_CREDENTIALS_DIR=None))
    )


def test_ca_bundle_must_exist(tmp_path):
    assert any(
        "PROXMOX_CA_BUNDLE" in p
        for p in problems(broker_env(tmp_path, PROXMOX_CA_BUNDLE=str(tmp_path / "no.pem")))
    )
    pem = tmp_path / "ca.pem"
    pem.write_text("x")
    assert config.load(broker_env(tmp_path, PROXMOX_CA_BUNDLE=str(pem))).proxmox_ca_bundle == str(
        pem
    )


def test_fingerprint_and_lists(tmp_path):
    assert any(
        "FINGERPRINT" in p for p in problems(broker_env(tmp_path, PROXMOX_TLS_FINGERPRINT="abcd"))
    )
    assert any(
        "FINGERPRINT" in p
        for p in problems(broker_env(tmp_path, PROXMOX_TLS_FINGERPRINT=PIN + ","))
    )
    assert any(
        "MCP_TOOL_DENY" in p for p in problems(broker_env(tmp_path, MCP_TOOL_DENY="(unclosed"))
    )
    assert any(
        "MCP_TOOL_ALLOW" in p for p in problems(broker_env(tmp_path, MCP_TOOL_ALLOW="list nodes"))
    )
    assert any("CF_ACCESS_AUD" in p for p in problems(broker_env(tmp_path, CF_ACCESS_AUD="short")))
    assert any(
        "MCP_ALLOWED_HOSTS" in p for p in problems(broker_env(tmp_path, MCP_ALLOWED_HOSTS="a b"))
    )
    s = config.load(
        broker_env(tmp_path, MCP_TOOL_DENY="^delete_,^destroy", MCP_ALLOWED_HOSTS="Broker.Internal")
    )
    assert s.tool_deny == ("^delete_", "^destroy") and s.allowed_hosts == ("broker.internal",)


def test_choices():
    assert any("MCP_TOOL_MODE" in p for p in problems(stdio_env(MCP_TOOL_MODE="Dynamic"), "stdio"))
    assert any("MCP_LOCAL_MODE" in p for p in problems(stdio_env(MCP_LOCAL_MODE="admin"), "stdio"))


def test_stdio_needs_token_and_not_root():
    assert any("stdio needs" in p for p in problems(stdio_env(PROXMOX_TOKEN_VALUE=None), "stdio"))
    assert any("root@pam" in p for p in problems(stdio_env(PROXMOX_USER="root@pam"), "stdio"))
    s = config.load(stdio_env(), role="stdio")
    assert s.proxmox_token_value.reveal().startswith("1b9d6bcd")


def test_stdio_does_not_require_broker_settings():
    s = config.load(stdio_env(), role="stdio")
    assert s.credentials_dir is None and s.dangerous_flags() == ()


def test_all_problems_reported_together(tmp_path):
    env = broker_env(
        tmp_path, PROXMOX_HOST=None, MCP_PORT="0", MCP_ALLOW_ADMIN_TOOLS="yes", MCP_TYPO="1"
    )
    assert len(problems(env)) >= 4


def test_error_messages_never_contain_values(tmp_path):
    secret = "s3cr3t-VALUE-0000"
    env = broker_env(
        tmp_path,
        **{
            "PROXMOX_TOKEN_VALUE": secret,
            "MCP_PORT": secret,
            "PROXMOX_HOST": secret + "/x",
            "MCP_ALLOW_ADMIN_TOOLS": secret,
            "CF_ACCESS_AUD": secret + " ",
            "MCP_UNKNOWN": secret,
            "PROXMOX_PASSWORD": secret,
        },
    )
    with pytest.raises(config.ConfigError) as ei:
        config.load(env)
    assert secret not in str(ei.value) and secret not in repr(ei.value)


def test_every_known_var_is_parsed():
    """KNOWN_VARS is the typo allowlist: each entry must be consumed by load()."""
    src = Path(config.__file__).read_text()
    body = src[src.index("def load(") : src.index("# ---- process-wide instance")]
    for name in config.KNOWN_VARS:
        assert f'"{name}"' in body, name


def test_every_env_name_in_package_is_known():
    """Every quoted PROXMOX_/MCP_/BROKER_/CF_ACCESS_ name in the package is declared here.

    Catches reads through helpers (_env_int("MCP_PORT"), _split_env(...)) as well as
    os.getenv / os.environ, so config.py stays the single list of settings.
    """
    pkg = Path(config.__file__).parent
    pattern = re.compile(r"""["']((?:PROXMOX|MCP|BROKER|CF_ACCESS)_[A-Z0-9_]*[A-Z0-9])["']""")
    names = set()
    for path in pkg.rglob("*.py"):
        if path.name != "config.py":
            names |= set(pattern.findall(path.read_text()))
    declared = set(config.KNOWN_VARS) | set(config.REMOVED_VARS)
    assert names, "pattern found nothing"
    assert names - declared == set()


def test_dangerous_flags_logged_and_audited(tmp_path, caplog):
    env = broker_env(tmp_path, MCP_ALLOW_ADMIN_TOOLS="1", MCP_ALLOW_SERVICE_TOKENS="1")
    config.reset_for_tests()
    assert config.audit_start_fields() == {}
    with pytest.raises(config.ConfigError):
        config.current()
    try:
        with caplog.at_level(logging.WARNING, logger="proxmox_mcp.config"):
            s = config.init("broker", env)
        warned = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert any("MCP_ALLOW_ADMIN_TOOLS" in m for m in warned)
        assert any("MCP_ALLOW_SERVICE_TOKENS" in m for m in warned)
        fields = config.audit_start_fields()
        assert fields["dangerous_flags"] == ["MCP_ALLOW_SERVICE_TOKENS", "MCP_ALLOW_ADMIN_TOOLS"]
        assert fields["config_sha256"] == s.config_sha256() and config.current() is s
    finally:
        config.reset_for_tests()


def test_config_hash_changes_with_settings(tmp_path):
    a = config.load(broker_env(tmp_path))
    b = config.load(broker_env(tmp_path, MCP_RATE_PER_MIN="30"))
    assert a.config_sha256() != b.config_sha256()
    assert a.config_sha256() == config.load(broker_env(tmp_path)).config_sha256()


def test_settings_never_expose_token():
    s = config.load(stdio_env(), role="stdio")
    secret = "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"
    for text in (
        repr(s),
        str(s),
        str(s.summary()),
        f"{s.proxmox_token_value}",
        repr(s.proxmox_token_value),
        str(s.proxmox_token_value),
    ):
        assert secret not in text
    assert s.summary()["proxmox_token_value"] == "<set>"


def test_secretstr_properties():
    a, b = config.SecretStr("x" * 36), config.SecretStr("x" * 36)
    assert a == b and a != config.SecretStr("y") and len(a) == 36 and bool(a)
    assert hash(a) == hash(b) and hash(a) != hash("x" * 36)
    with pytest.raises(TypeError):
        pickle.dumps(a)
    with pytest.raises(AttributeError):
        a._value = "z"
    with pytest.raises(TypeError):
        config.SecretStr(b"bytes")
    assert format(a, "") == "<redacted>" and "%s" % (a,) == "<redacted>"  # noqa: UP031
