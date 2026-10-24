"""H4 red team: PHI redaction false negatives (HIPAA 164.502(b) minimum necessary).

Every case here was a bypass of the original phi.py: the value reached the model
(read path) or Proxmox (write path) unredacted.
"""

import base64
import json
import re

import pytest

from proxmox_mcp import output
from proxmox_mcp.phi import detect_phi, redact_phi

ZWJ, ZWSP, ZWNJ, WJ, SHY = "‍", "​", "‌", "⁠", "­"


def fw(s: str) -> str:
    """Fullwidth form of ASCII digits/letters/hyphen."""
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in s)


def arabic_indic(s: str) -> str:
    return "".join(chr(0x0660 + int(c)) if c.isdigit() else c for c in s)


SSN_BYPASSES = [
    "123.45.6789",
    "123 45 6789",
    fw("123-45-6789"),
    arabic_indic("123-45-6789"),
    "1" + ZWJ + "23-45-6789",
    ZWSP.join("123-45-6789"),
    "SSN:" + ZWNJ.join("123456789"),
    "123" + SHY + "-45-6789",
    "123‑45‑6789",  # non-breaking hyphens
    "123–45–6789",  # en dashes
    "123−45−6789",  # minus signs
    "123－45－6789",  # fullwidth hyphen-minus
    "SSN:123-45-6789abc",  # labelled, trailing letters
    "ssn123456789",
    "patient_ssn=123456789",
    "Social Security No. 123456789",
    "soc. sec. #: 123 45 6789",
    "numero de seguro social: 123-45-6789",
    "número de seguro social 123456789",
    '"ssn": "123456789"',
    "SSN 123 45 6789",  # no-break spaces
    "SSN 123-45-6789X",  # HICN-like suffix
]


@pytest.mark.parametrize("text", SSN_BYPASSES)
def test_ssn_variants_detected_and_redacted(text):
    assert detect_phi(text) is not None, text
    red = redact_phi(text)
    assert "[REDACTED" in red
    digits = "".join(c for c in red if c.isdigit())
    assert "6789" not in digits and "٦٧٨٩" not in red, red


MBI_BYPASSES = [
    "1eg4-te5-mk73",
    "member 1eg4te5mk73",
    fw("1EG4-TE5-MK73"),
    "1EG4" + ZWJ + "TE5MK73",
    "Medicare ID: 1EG4TE5MK73",
    "HICN 123456789A",
    "medicare #123-45-6789a",
]


@pytest.mark.parametrize("text", MBI_BYPASSES)
def test_mbi_variants(text):
    assert detect_phi(text) in ("mbi", "ssn"), text
    assert "MK73" not in redact_phi(text).upper()


MRN_BYPASSES = [
    "MR#: 00123456",
    "MR # 00123456",
    "MR No. 00123456",
    "Med Rec #A123456",
    "med. rec. no. 445566",
    "medical record no: 99887766",
    "medical-record-number=12345678",
    "patient_mrn=12345678",
    "patient id: 7788990",
    "Patient ID# A778899",
    "pt id 7788990",
    "chart #: 556677",
    "chart number 556677",
    "acct/MRN 12345678",
    "MRN12345678",
    '"mrn": "12345678"',
    "mrn: 0012 3456",
    "EMR #: 123456",
    "EHR ID 123456",
    "health record number 1234567",
    "hospital number: 1234567",
    "unit number 1234567",
    "número de expediente: 1234567",
    "numero de expediente 1234567",
    "expediente médico 1234567",
    "historia clínica nº 1234567",
    "historia clinica: 1234567",
    "registro médico 1234567",
    "numéro de dossier: 1234567",
    "dossier médical 1234567",
    "prontuário 1234567",
    "病历号: 1234567",
    "病歷號 1234567",
    "số hồ sơ: 1234567",
    "номер медицинской карты 1234567",
    "MRN" + ZWJ + ": 12345678",
    fw("MRN: 12345678"),
]


@pytest.mark.parametrize("text", MRN_BYPASSES)
def test_mrn_label_spellings(text):
    assert detect_phi(text) == "mrn", text
    red = redact_phi(text)
    assert "[REDACTED mrn]" in red and not re.search(r"[0-9]{3}", red.replace(" ", "")), red


DOB_BYPASSES = [
    "DOB 1/2/80",
    "DOB: 01-02-1980",
    "DOB: 01.02.1980",
    "DOB 1980/02/01",
    "DOB:19800201",
    "dob=1980-02-01",
    "D.O.B. 02 Jan 1980",
    "DOB 02-Jan-1980",
    "DOB 02Jan1980",
    "DOB: Jan 2nd, 1980",
    "DOB January 2nd 1980",
    "DOB: 2nd of January, 1980",
    "DOB 1980-Jan-02",
    "DOB: 1980-02-01T00:00:00Z",
    "DOB 01 / 02 / 1980",
    "date of birth: 2 January 1980",
    "Date-of-Birth: 1980-02-01",
    "birthday: 01/02/1980",
    "born on 01/02/1980",
    "patient_dob=01/02/1980",
    '"dob": "1980-02-01"',
    "B-Date: 01/02/1980",
    "bdate 01/02/1980",
    "fecha de nacimiento: 02/01/1980",
    "fecha de nac.: 02/01/1980",
    "F. nac. 02/01/1980",
    "FDN: 02/01/1980",
    "nacido el 2 de enero de 1980",
    "date de naissance : 02/01/1980",
    "née le 02/01/1980",
    "data de nascimento: 02/01/1980",
    "出生日期: 1980-02-01",
    "ngày sinh: 02/01/1980",
    "생년월일: 1980-02-01",
    "дата рождения: 02.01.1980",
    "petsa ng kapanganakan: 01/02/1980",
    "DOB" + ZWJ + ": 01/02/1980",
    fw("DOB: 01/02/1980"),
]


@pytest.mark.parametrize("text", DOB_BYPASSES)
def test_dob_formats(text):
    assert detect_phi(text) == "dob", text
    red = redact_phi(text)
    assert "[REDACTED dob]" in red and not re.search(r"[0-9]", red), red


CARD_BYPASSES = [
    "4111.1111.1111.1111",
    "4111  1111  1111  1111",
    fw("4111 1111 1111 1111"),
    ZWJ.join("4111111111111111"),
    "4111–1111–1111–1111",
    "card:4111111111111111.",
    "5555-5555-5555-4444",
    "3782 822463 10005",
]


@pytest.mark.parametrize("text", CARD_BYPASSES)
def test_card_formats(text):
    assert detect_phi(text) == "card", text
    assert "[REDACTED card]" in redact_phi(text)


def test_original_text_preserved_around_redaction():
    text = "Ｖｍ ｎｏｔｅ ✓ — SSN " + fw("123-45-6789") + " ok ✓"
    red = redact_phi(text)
    assert (
        red.startswith("Ｖｍ ｎｏｔｅ ✓ — SSN ")
        and red.endswith(" ok ✓")
        and "[REDACTED ssn]" in red
    )


# --- structure: keys, split values, encodings -------------------------------------------------


def body(text):
    lines = text.split("\n")
    return json.loads("\n".join(lines[2:-1]))


@pytest.mark.parametrize(
    "data, leaked",
    [
        ({"ssn": "123456789"}, "123456789"),
        ({"SSN": 123456789}, "123456789"),
        ({"patientDOB": "1980-02-01"}, "1980"),
        ({"date_of_birth": {"y": 1980, "m": 2, "d": 1}}, "1980"),
        ({"dob_year": 1980, "dob_month": 2}, "1980"),
        ({"mrn": "A12"}, "A12"),
        ({"medicare_id": "1EG4TE5MK73"}, "MK73"),
        ({"MedicalRecordNumber": "00123456"}, "00123456"),
        ({"credit_card_number": "4111111111111111"}, "41111111"),
        ({"ssn_area": "123", "ssn_group": "45", "ssn_serial": "6789"}, "6789"),
    ],
)
def test_phi_keys_redact_values(data, leaked):
    out = output.render_result({"data": data})
    assert leaked not in out, out
    assert detect_phi(data) is not None


@pytest.mark.parametrize(
    "data, leaked",
    [
        ({"label": "SSN", "value": "123456789"}, "123456789"),
        ({"field": "DOB", "value": "01/02/1980"}, "1980"),
        ({"k": "MRN", "v": 12345678}, "12345678"),
        (["Date of birth", "1980-02-01"], "1980-02-01"),
        ({"name": "password", "value": "hunter2xyz"}, "hunter2xyz"),
    ],
)
def test_phi_split_across_sibling_values(data, leaked):
    out = output.render_result({"data": data})
    assert leaked not in out, out
    if "password" not in str(data):
        assert detect_phi(data) is not None


def test_phi_in_dict_keys_redacted_on_read():
    out = output.render_result({"data": {"SSN 123-45-6789": 1, "DOB: 01/02/1980": 2, "vmid": 100}})
    assert "6789" not in out and "1980" not in out
    b = body(out)["data"]
    assert b["vmid"] == 100 and len(b) == 3  # colliding redacted keys do not overwrite each other


def test_redacted_key_collisions_keep_both_entries():
    b = body(output.render_result({"SSN 123-45-6789": "a", "SSN 223-45-6789": "b"}))
    assert len(b) == 2 and "6789" not in json.dumps(b)  # PHI-labelled keys also redact their values


FREE_TEXT_FIELDS = [
    (
        "vm description",
        {"data": {"description": "Pt: J. Doe\nDOB: 01/02/1980\nMRN: 88776655", "vmid": 101}},
    ),
    ("tags", {"data": [{"vmid": 102, "tags": "prod;mrn-88776655;dob-1980-02-01"}]}),
    ("pool comment", {"data": [{"poolid": "radiology", "comment": "owner ssn 123-45-6789"}]}),
    (
        "snapshot",
        {
            "data": [
                {
                    "name": "pre-upgrade",
                    "description": "patient 1EG4-TE5-MK73 test",
                    "snaptime": 1712345678,
                }
            ]
        },
    ),
    (
        "task log",
        {
            "data": [
                {"n": 1, "t": "INFO: restoring for MRN#88776655"},
                {"n": 2, "t": "INFO: SSN 123 45 6789 found"},
            ]
        },
    ),
    ("cloud-init", {"data": "#cloud-config\nwrite_files:\n- content: 'dob: 1980-02-01'\n"}),
    ("lxc notes", {"data": {"description": "patient_ssn%3D123-45-6789", "hostname": "ct1"}}),
]


@pytest.mark.parametrize("where, data", FREE_TEXT_FIELDS, ids=[w for w, _ in FREE_TEXT_FIELDS])
def test_free_text_fields(where, data):
    out = output.render_result(data)
    for leak in ("88776655", "6789", "1980-02-01", "01/02/1980", "MK73"):
        assert leak not in out, (where, out)


def b64(s: str, urlsafe=False) -> str:
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return enc(s.encode()).decode()


@pytest.mark.parametrize(
    "payload",
    [
        b64("patient SSN 123-45-6789"),
        b64("DOB: 01/02/1980 MRN: 88776655"),
        b64("#cloud-config\nusers:\n - name: x\n   gecos: 'MRN 88776655'\n"),
        b64("ssn=123456789", urlsafe=True).rstrip("="),
        b64(b64("SSN 123-45-6789")),
    ],
)
def test_base64_encoded_phi(payload):
    assert detect_phi(payload) is not None
    out = output.render_result({"data": {"userdata": "x " + payload + " y", "vmid": 1}})
    assert payload not in out and "[REDACTED" in out


@pytest.mark.parametrize(
    "text",
    [
        "SSN%3A%20123-45-6789",
        "dob%3D01%2F02%2F1980",
        "MRN&#58; 88776655",
        "SSN\\u003a 123-45-6789",
        "dob=01%2F02%2F1980",
    ],
)
def test_percent_html_and_escape_encoded_phi(text):
    assert detect_phi(text) is not None, text
    red = redact_phi(text)
    assert "6789" not in red and "1980" not in red and "88776655" not in red, red


def test_detect_phi_fails_closed_on_unscannable():
    deep = cur = {}
    for _ in range(100):
        cur["a"] = {}
        cur = cur["a"]
    assert detect_phi(deep) is not None
    assert detect_phi({"x": b"SSN 123-45-6789"}) == "ssn"


@pytest.mark.parametrize(
    "text",
    [
        "1́23-45-6789",  # combining acute on a digit
        "1️23-45-6789",  # variation selector
        "1ㅤ23-45-6789",  # Hangul filler (renders blank, category Lo)
        "1ﾠ23-45-6789",  # halfwidth Hangul filler
        "SSN 12͏3456789",  # combining grapheme joiner
        "123-45-67\U000e004189",  # tag character
        "\U0001d7cf\U0001d7d0\U0001d7d1-\U0001d7d2\U0001d7d3-\U0001d7d4\U0001d7d5\U0001d7d6\U0001d7d7",  # math bold
        "¹²³-⁴⁵-⁶⁷⁸⁹",  # superscripts
        "ssn: 123 456789",  # thin space
        "1⃝23-45-6789",  # enclosing mark
    ],
)
def test_invisible_and_compatibility_characters(text):
    assert detect_phi(text) == "ssn", ascii(text)
    assert "[REDACTED ssn]" in redact_phi(text)
