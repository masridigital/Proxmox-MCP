"""H3 red team: path canonicalization and method tricks against outbound.check."""

import pytest

from proxmox_mcp import outbound

BLOCKED = "blocked by outbound policy"


@pytest.mark.parametrize(
    "path",
    [
        # double encoding: %25 is never an allowed escape
        "/nodes/pve/storage/local/content/a%252F..%252Fb",
        "/nodes/%252e%252e/access/users",
        # encoded dots, any case
        "/nodes/%2e%2e/access/users",
        "/nodes/pve/storage/local/content/%2E",
        # overlong / invalid UTF-8 for "/" and "."
        "/nodes/pve/storage/local/content/%c0%af",
        "/nodes/pve/storage/local/content/%C0%AE%C0%AE",
        "/nodes/pve/storage/local/content/%e0%80%af",
        # mixed-case allowed escape that decodes to a dot segment
        "/nodes/pve/storage/local/content/a%2f.%2fb",
        "/nodes/pve/storage/local/content/a%2F..",
        "/nodes/pve/storage/local/content/%2fetc",
        # ;params (servlet-style) must not reach a deny/allow decision on a different reading
        "/access/ticket;x",
        "/nodes/pve/qemu/100/agent/exec;x",
        "/nodes/pve;x/qemu",
        # trailing dot segments
        "/nodes/pve/qemu/100/status/current/.",
        "/nodes/pve/qemu/100/status/current/..",
        "/nodes/pve/.",
        # backslash, tab, CR/LF, NUL, vertical tab, form feed, unicode separators
        "/nodes\\pve",
        "/nodes/pve%5cqemu",
        "/nodes/pve\t",
        "/nodes/pve\r\n",
        "/nodes/pve\x0b",
        "/nodes/pve\x0c",
        "/nodes/pve\u2028",
        "/nodes/pve\u00a0",
        # other punctuation never used by the tools
        "/nodes/pve$x",
        "/nodes/pve'x",
        "/nodes/pve\"x",
        "/nodes/pve<x>",
        "/nodes/pve|x",
        "/nodes/pve*",
        "/nodes/~pve",
        "/nodes/pve&x=1",
        # absolute-form / authority smuggling
        "//evil.example.com/api2/json/nodes",
        "/@evil.example.com/nodes",
        "http://evil.example.com/nodes",
        "",
    ],
)
def test_canonicalization_tricks_blocked(path):
    with pytest.raises(PermissionError, match=BLOCKED):
        outbound.check("GET", path, "rw")


@pytest.mark.parametrize(
    "path,reason",
    [
        # Allowed escapes that decode into a denied endpoint are judged on the decoded path too.
        ("/nodes/pve/storage/local/content/x%2Fvncshell", "console / shell access"),
        ("/nodes/pve/storage/local/content/x%2Ftermproxy", "console / shell access"),
        ("/nodes/pve/storage/local/content/a%2Fagent%2Fexec", "guest agent"),
    ],
)
def test_deny_rules_see_decoded_path(path, reason):
    with pytest.raises(PermissionError, match=reason):
        outbound.check("GET", path, "rw")


@pytest.mark.parametrize(
    "method",
    ["get", "Get", "GET ", " GET", "GET\r\n", "G\x00ET", "HEAD", "OPTIONS", "PATCH", "TRACE",
     "CONNECT", "PROPFIND", "", None, 1, b"GET", ["GET"], "POſT", "DELETE\t"],
)
def test_method_smuggling(method):
    with pytest.raises(PermissionError, match=BLOCKED):
        outbound.check(method, "/nodes", "rw")


@pytest.mark.parametrize("mode", ["RW", "rw ", "admin", "", None, "operator\n"])
def test_mode_must_be_exact(mode):
    with pytest.raises(PermissionError, match="unknown mode"):
        outbound.check("GET", "/nodes", mode)


@pytest.mark.parametrize("value", ["pve01\n", "pve\r", "a\x00", "\npve", "pve\t"])
def test_safe_segment_trailing_newline(value):
    # "$" in a regex matches before a trailing newline; validation must use fullmatch.
    with pytest.raises(ValueError):
        outbound.safe_segment(value)


def test_allowlist_templates_are_anchored_at_end():
    # A placeholder must never swallow a trailing newline that slipped past validate_path.
    for patterns in outbound._ALLOW.values():
        for p in patterns:
            assert not p.match(p.pattern.replace("^", "").replace("$", "").replace("\\Z", "") + "\n")
    for patterns in outbound._ALLOW.values():
        for p in patterns:
            assert p.pattern.endswith("\\Z")


def test_legit_paths_still_pass():
    outbound.check("GET", "/nodes/pve/storage/local/content/local%3Aiso%2Fdebian.iso", "rw")
    outbound.check("GET", "/nodes/pve/storage/local/content/local%3aiso%2fdebian.iso", "rw")
    outbound.check("GET", "/nodes/pve/tasks/UPID:pve:0000ABCD:0123ABCD:65A1B2C3:qmstart:100:root@pam!t:/log", "ro")
    outbound.check("DELETE", "/cluster/firewall/ipset/blk/192.0.2.0%2F24", "rw")
    outbound.check("GET", "/access/users/mcp-alice+x@pve", "ro")
