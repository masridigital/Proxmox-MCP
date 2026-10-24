"""H8 patch E1: enrollment.json token_expires (optional ISO date), enforced fail closed."""

import datetime as dt
import json

import pytest

from proxmox_mcp import enrollment
from proxmox_mcp.identity import Identity

ENTRY = {"mode": "ro", "proxmox_userid": "mcp-a@pve", "token_credential": "pve-token-a"}


def test_token_expires_parsed():
    doc = {"users": {"a@example.com": {**ENTRY, "token_expires": "2027-01-31"}}}
    assert enrollment.parse_enrollments(doc)["a@example.com"].token_expires == dt.date(2027, 1, 31)
    plain = enrollment.parse_enrollments({"users": {"a@example.com": ENTRY}})
    assert plain["a@example.com"].token_expires is None


@pytest.mark.parametrize(
    "value", ["2027-1-31", "31/01/2027", "2027-02-30", 20270131, None, "", "2027-01-31T00:00"]
)
def test_token_expires_strict(value):
    with pytest.raises(enrollment.EnrollmentError, match="token_expires"):
        enrollment.parse_enrollments(
            {"users": {"a@example.com": {**ENTRY, "token_expires": value}}}
        )


def test_unknown_keys_still_rejected():
    with pytest.raises(enrollment.EnrollmentError, match="unknown keys"):
        enrollment.parse_enrollments(
            {"users": {"a@example.com": {**ENTRY, "token_expiry": "2027-01-31"}}}
        )


def test_expired_token_denied(tmp_path, monkeypatch):
    today = dt.datetime.now(dt.timezone.utc).date()
    path = tmp_path / "enrollment.json"
    path.write_text(
        json.dumps(
            {
                "users": {
                    "a@example.com": {**ENTRY, "token_expires": today.isoformat()},
                    "b@example.com": {
                        **ENTRY,
                        "proxmox_userid": "mcp-b@pve",
                        "token_credential": "pve-token-b",
                        "token_expires": (today + dt.timedelta(days=1)).isoformat(),
                    },
                }
            }
        )
    )
    monkeypatch.setenv("MCP_ENROLLMENT_FILE", str(path))
    enrollment._cache.clear()
    with pytest.raises(PermissionError, match="token expired"):
        enrollment.enrollment_for(Identity("a@example.com", "user", email="a@example.com"))
    b = enrollment.enrollment_for(Identity("b@example.com", "user", email="b@example.com"))
    assert b.mode == "ro"
