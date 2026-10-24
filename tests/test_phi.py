"""PHI detection (writes) and redaction (results), with infrastructure false-positive checks."""

import pytest

from proxmox_mcp.phi import detect_phi, redact_phi

POSITIVE = [
    ("SSN 123456789", "ssn"),
    ("ssn: 123 45 6789", "ssn"),
    ("social security number 123-45-6789", "ssn"),
    ("123-45-6789", "ssn"),
    ("1EG4-TE5-MK73", "mbi"),
    ("member 1EG4TE5MK73", "mbi"),
    ("MRN: 00123456", "mrn"),
    ("medical record number A12-3456", "mrn"),
    ("DOB: 01/02/1980", "dob"),
    ("date of birth March 3, 1975", "dob"),
    ("birthdate 1980-02-01", "dob"),
    ("card 4111 1111 1111 1111", "card"),
    ("4111-1111-1111-1111", "card"),
    ("378282246310005", "card"),
    ("5555555555554444", "card"),
    ("6011111111111117", "card"),
]

NEGATIVE = [
    "100", "9999", "vm-100-disk-0", "BC:24:11:00:01:1E", "bc-24-11-00-01-1e",
    "550e8400-e29b-41d4-a716-446655440000", "10.0.0.21/24", "192.0.2.10", "fd00::1/64",
    "17179869184", "1099511627776", "34359738368000",
    "UPID:pve01:0000ABCD:0123ABCD:65A1B2C3:qmstart:100:root@pam:",
    "UPID:pve01:002B1C3D:01A2B3C4:6720F1A2:vzdump:101:dev@pve!mcp:",
    "2024-01-15", "created 2024-01-15T10:00:00Z", "4111111111111112", "000-12-3456",
    "666-12-3456", "local:iso/ubuntu-24.04.iso", "order=1,up=10,down=5",
    "sha256:9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
]


@pytest.mark.parametrize("text, kind", POSITIVE)
def test_detects(text, kind):
    assert detect_phi(text) == kind
    redacted = redact_phi(text)
    assert f"[REDACTED {kind}]" in redacted


@pytest.mark.parametrize("text", NEGATIVE)
def test_no_false_positive(text):
    assert detect_phi(text) is None
    assert redact_phi(text) == text


def test_nested_and_keys():
    assert detect_phi({"a": [{"b": ("x", "MRN 1234567")}]}) == "mrn"
    assert detect_phi({"SSN 123-45-6789": 1}) == "ssn"
    assert detect_phi({"vmid": 100, "size": 17179869184, "mac": "BC:24:11:00:01:1E"}) is None


def test_numbers_not_scanned():
    assert detect_phi({"x": 4111111111111111}) is None


def test_contact_flag(monkeypatch):
    monkeypatch.delenv("MCP_PHI_CONTACT", raising=False)
    assert detect_phi("mail a.person@example.com, call 202-555-0143") is None
    monkeypatch.setenv("MCP_PHI_CONTACT", "1")
    assert detect_phi("mail a.person@example.com") == "email"
    assert detect_phi("call 202-555-0143") == "phone"
