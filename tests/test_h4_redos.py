"""H4 red team: redaction cost DoS. Every pattern must run in linear time on adversarial input.

Python's re has no timeout, so linearity is a property of the patterns themselves: bounded
quantifiers, lookbehind-anchored run starts, no nested ambiguous quantifiers. A quadratic
pattern on a 100 KB input takes minutes; the bounds below are two orders of magnitude loose.
"""

import time

import pytest

from proxmox_mcp import output, phi

N = 100_000

ADVERSARIAL = {
    "digits": "1" * N,
    "digit-dash": "1-" * (N // 2),
    "digit-space": "1 " * (N // 2),
    "digit-dot": "1." * (N // 2),
    "ssn-like": "123-45-" * (N // 7),
    "card-groups": "4111 " * (N // 5),
    "letters": "a" * N,
    "upper-alnum": "A1" * (N // 2),
    "mbi-ish": "1EG4-TE5-" * (N // 9),
    "spaces": " " * N,
    "ssn-labels": "ssn " * (N // 4),
    "ssn-label-space": "SSN" + " " * N,
    "social": "social " * (N // 7),
    "mrn-dashes": "MRN-" * (N // 4),
    "mrn-run": "MRN " + "A-" * (N // 2),
    "med-rec": "med rec " * (N // 8),
    "dob-labels": "DOB: 1/" * (N // 7),
    "dob-month": "DOB jan " * (N // 8),
    "dob-de": "nacido el 2 de " * (N // 15),
    "email-local": "a." * (N // 2),
    "email-at": "a@" * (N // 2),
    "email-domain": "a@" + "b." * (N // 2),
    "phone": "202-555-" * (N // 8),
    "pem-begin": "-----BEGIN " * (N // 11),
    "pem-open": "-----BEGIN RSA PRIVATE KEY-----" + "A" * N,
    "pem-many": "-----BEGIN RSA PRIVATE KEY-----\n" * (N // 32),
    "putty": "PuTTY-User-Key-File-2: " * (N // 23),
    "jwt-eyj": "eyJ" * (N // 3),
    "jwt-dots": "eyJaaaaaaaaa." * (N // 13),
    "b64": "QUFB" * (N // 4),
    "b64-printable": "U1NOIDEyMy00NS02Nzg5IA==" * (N // 24),
    "percent": "%41" * (N // 3),
    "percent-bad": "%4" * (N // 2),
    "html-ent": "&#58;" * (N // 5),
    "uescape": "\\u0031" * (N // 6),
    "password-labels": "password=" * (N // 9),
    "token-colon": "token: " * (N // 7),
    "url-userinfo": "https://a:" * (N // 10),
    "bearer": "bearer " * (N // 7),
    "fullwidth": "１" * N,
    "zwj-digits": "1‍" * (N // 2),
    "mixed-nonascii": "é1-" * (N // 3),
    "pve-ticket": "PVE:a:" * (N // 6),
    "akia": "AKIA" * (N // 4),
    "azure-q": "abc8Q~" * (N // 6),
    "sshkeys": "sshkeys=" + "a " * (N // 2),
    "cli-flags": "--password " * (N // 11),
}


def _all_patterns():
    pats = list(phi.PATTERNS.items()) + list(output.SECRET_PATTERNS.items())
    assert len(pats) > 20
    return pats


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_each_pattern_linear(name):
    text = ADVERSARIAL[name]
    for pname, rx in _all_patterns():
        t0 = time.perf_counter()
        for _ in rx.finditer(text):
            pass
        dt = time.perf_counter() - t0
        assert dt < 0.5, (pname, name, dt)


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_full_redaction_bounded(name):
    text = ADVERSARIAL[name]
    t0 = time.perf_counter()
    output.redact_text(text)
    phi.detect_phi(text)
    assert time.perf_counter() - t0 < 4.0, name


@pytest.mark.parametrize(
    "name",
    [
        "ssn-like",
        "mrn-dashes",
        "email-local",
        "jwt-eyj",
        "b64-printable",
        "zwj-digits",
        "dob-labels",
        "percent",
    ],
)
def test_scaling_is_linear(name):
    def t(n):
        text = ADVERSARIAL[name][:n]
        best = 1e9
        for _ in range(3):
            t0 = time.perf_counter()
            output.redact_text(text)
            best = min(best, time.perf_counter() - t0)
        return best

    small, big = t(N // 8), t(N)
    # 8x input: linear ~8x, quadratic ~64x. Allow generous noise.
    assert big < small * 20 + 0.05, (name, small, big)


def test_structure_redaction_bounded():
    wide = {f"k{i}": "SSN 123-45-6789" for i in range(20000)}
    t0 = time.perf_counter()
    out = output.render_result(wide)
    assert time.perf_counter() - t0 < 5.0
    assert "123-45" not in out
