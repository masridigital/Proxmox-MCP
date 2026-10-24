"""PHI pattern detection and redaction (HIPAA 164.502(b), minimum necessary).

Proxmox does not hold clinical data, but free-text fields (VM/CT names, notes,
descriptions, tags, pool comments) can. This module:
  - detect_phi(value): walks nested data and returns the first PHI type found,
    used by the client to refuse POST/PUT bodies (PermissionError);
  - redact_phi(text): replaces matches with "[REDACTED <type>]" on results.

Patterns are deliberately narrow to stay quiet on infrastructure data (VMIDs, MACs,
UUIDs, IPs, byte sizes, UPIDs, ISO dates without a DOB label):
  ssn       ddd-dd-dddd with SSA validity rules, or 9 digits / spaced form next to an
            "SSN" / "social security" label;
  mbi       Medicare Beneficiary Identifier (CMS format, uppercase, optional dashes);
  mrn       a number labelled MRN / medical record (number|no|#);
  dob       a date labelled DOB / date of birth / birth date;
  card      13-19 digits (optionally grouped by space/dash) with a known card prefix
            and length (Visa, Mastercard, Amex, Discover) that pass the Luhn check;
  email / phone  only when MCP_PHI_CONTACT=1 (contacts are often operational data).
Only strings are scanned: numbers in JSON are sizes, counters and ids.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from typing import Any

_SSN_DASHED = re.compile(r"(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])")
_SSN_LABELLED = re.compile(
    r"(?i)\b(?:ssn|ss#|social\s+security(?:\s+(?:number|no\.?|#))?)\s*[:#=]?\s*"
    r"(?!000|666|9\d\d)\d{3}[\s-]?(?!00)\d{2}[\s-]?(?!0000)\d{4}\b"
)
# CMS MBI: N A AN N - A AN N - A A N N ; A excludes S L O I B Z.
_A = "[AC-HJKMNP-RT-Y]"
_AN = "[AC-HJKMNP-RT-Y0-9]"
_MBI = re.compile(
    rf"(?<![A-Za-z0-9-])[1-9]{_A}{_AN}[0-9]-?{_A}{_AN}[0-9]-?{_A}{_A}[0-9]{{2}}(?![A-Za-z0-9-])"
)
_MRN = re.compile(
    r"(?i)\b(?:mrn|medical\s+record(?:\s+(?:number|no\.?|#))?)\s*[:#=]?\s*"
    r"(?=[A-Z0-9-]*\d)[A-Z0-9][A-Z0-9-]{3,19}\b"
)
_DATE = (
    r"(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{1,2}-\d{1,2}|"
    r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}|"
    r"\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{4})"
)
_DOB = re.compile(
    rf"(?i)\b(?:dob|d\.o\.b\.?|date\s+of\s+birth|birth\s*date|born(?:\s+on)?)\s*[:=]?\s*{_DATE}"
)
_CARD = re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<![\w-])(?:\+?1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]?[2-9]\d{2}[\s.-]?\d{4}(?![\w-])")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_brand_ok(digits: str) -> bool:
    n = len(digits)
    if digits[0] == "4":
        return n in (13, 16, 19)
    if n == 16 and (51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720):
        return True
    if n == 15 and digits[:2] in ("34", "37"):
        return True
    if 16 <= n <= 19 and (
        digits.startswith("6011") or digits.startswith("65") or 644 <= int(digits[:3]) <= 649
    ):
        return True
    return False


def _card_matches(text: str) -> Iterator[re.Match[str]]:
    for m in _CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _card_brand_ok(digits) and _luhn_ok(digits):
            yield m


def _contact_enabled() -> bool:
    return os.environ.get("MCP_PHI_CONTACT", "0").lower() in ("1", "true", "yes")


def _rules() -> list[tuple[str, Any]]:
    rules: list[tuple[str, Any]] = [
        ("ssn", _SSN_LABELLED.finditer),
        ("ssn", _SSN_DASHED.finditer),
        ("mbi", _MBI.finditer),
        ("mrn", _MRN.finditer),
        ("dob", _DOB.finditer),
        ("card", _card_matches),
    ]
    if _contact_enabled():
        rules += [("email", _EMAIL.finditer), ("phone", _PHONE.finditer)]
    return rules


def find_phi_in_text(text: str) -> str | None:
    for kind, finder in _rules():
        for _ in finder(text):
            return kind
    return None


def redact_phi(text: str) -> str:
    """Replace every PHI match with "[REDACTED <type>]"."""
    for kind, finder in _rules():
        matches = list(finder(text))
        for m in reversed(matches):
            text = text[: m.start()] + f"[REDACTED {kind}]" + text[m.end() :]
    return text


def detect_phi(value: Any, _depth: int = 0) -> str | None:
    """The first PHI type found anywhere in value (strings, dict keys and values), or None."""
    if _depth > 64:
        return None
    if isinstance(value, str):
        return find_phi_in_text(value)
    if isinstance(value, dict):
        for key, item in value.items():
            found = detect_phi(key, _depth + 1) or detect_phi(item, _depth + 1)
            if found:
                return found
        return None
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            found = detect_phi(item, _depth + 1)
            if found:
                return found
    return None
