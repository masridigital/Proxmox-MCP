"""PHI pattern detection and redaction (HIPAA 164.502(b), minimum necessary).

Proxmox does not hold clinical data, but free-text fields (VM/CT names, notes,
descriptions, tags, pool comments, snapshot descriptions, task logs, cloud-init) can.
  - detect_phi(value): the first PHI type in nested data, used by the client to refuse
    POST/PUT bodies (PermissionError). Fails closed: unscannable input is reported.
  - redact_phi(text): replaces matches with "[REDACTED <type>]" on results.
  - find_spans / apply_spans / cross_hits: the scan engine output.py reuses for secrets.

Scanning runs on a NORMALIZED VIEW of each string; the replacement is applied to the
original text, so data outside a match is returned byte-for-byte. Normalization:
  - invisible characters are dropped: categories Cf (zero-width space/joiners, word joiner,
    soft hyphen, BOM, bidi controls, tag characters), Mn/Me (combining and enclosing marks,
    variation selectors, U+034F), Cc (C1 controls), and the blank-rendering letters U+115F,
    U+1160, U+3164, U+FFA0, U+2800;
  - every Unicode decimal digit becomes its ASCII digit (fullwidth, Arabic-Indic, ...);
  - dash look-alikes (U+2010-2015, U+2212, U+FE58, U+FE63, U+FF0D, U+2043) become "-";
  - other non-ASCII characters are NFKD-folded to ASCII when that removes only combining
    marks ("número" -> "numero", fullwidth letters -> ASCII), else NFKC (CJK, Hangul,
    Cyrillic stay as they are); non-ASCII whitespace becomes " ";
  - inline encodings are decoded: %XX runs (UTF-8), HTML character references
    (&#58; &#x3a; &lt; &gt; &amp; &quot; &apos; &colon; &num; &sol; &nbsp;), \\uXXXX and \\xXX.
Base64 / base64url runs of 16+ characters are decoded (2 levels deep); if the decoded
text is printable UTF-8 and contains PHI (or, for output.py, a secret) the whole run is
replaced.

Patterns (all case-insensitive, on the normalized view; "v" = the redacted part):
  ssn   labelled: SSN | SS# | SS no/num | soc(ial) sec(urity) [no/num/#] | [numero de]
        seguro social, then 3-2-4 digits with optional [ .-] separators (SSA rules: area
        not 000/666/9xx, group not 00, serial not 0000); unlabelled: 3-2-4 digits with the
        SAME separator ("-", "." or " "), SSA rules, not inside a longer id/number;
  mbi   Medicare Beneficiary Identifier (CMS: N A AN N -? A AN N -? A A N N, letters exclude
        S L O I B Z), any case; labelled Medicare/MBI/HICN/beneficiary id + 9-13 alnum;
  mrn   labelled: MRN, MR#/no/num, med(ical) rec(ord)(s) [no/num/#/id], patient id/no/#,
        pt id/#, chart #/no/id, EMR/EHR #/id/no, health record [no/#/id], hospital no/#/id,
        unit no/#, (numero|no|n) de expediente, expediente [medico], historia clinica [no],
        registro medico, [numero de] dossier [medical], prontuario, 病历号/病歷號,
        so ho so [benh an], номер медицинской карты, медицинская карта
        -> value of 4-25 [A-Z0-9./-] containing a digit (plus space-separated digit groups);
  dob   labelled: DOB, D.O.B., date of birth, birth date, birthdate, birthday, b-date,
        born [on], fecha de nac(imiento), F. nac., FDN, nacido/nacida [el], date de
        naissance, ne/nee le, data de nascimento, 出生日期, ngay sinh, 생년월일,
        дата рождения, petsa ng kapanganakan -> a date: d/m/y in any order with / . - and
        spaces, yyyymmdd, month names (English, Spanish, French) with ordinals, "2 de enero
        de 1980", "2nd of January", CJK 年月日, optional ISO time;
  card  13-19 digits (single/double space, dash or dot separators), Visa/MC/Amex/Discover
        prefix + length, Luhn valid, not part of a longer id or a decimal number;
  email / phone  only when MCP_PHI_CONTACT=1 (contacts are often operational data).
Label boundaries: a Latin/Cyrillic label must not be preceded by a letter or digit, nor
followed by a letter ("adobe" is not DOB, "S4MBI123" is not a label, "patient_dob=" and
"MRN12345678" are); CJK/Hangul labels (病历号 病歷號 病案号 등록번호 환자번호 出生日期
出生年月日 생년월일) need no boundary. Label-value separator: up to 4 of [space " ' +], an optional
[: # = -] (1-2), up to 4 of [space " ' +].

PHI-named keys (redacted wholesale, any value type): see PHI_KEY_RE. Keys are split on
non-alphanumerics and camelCase, lowercased, joined with "_".

Every pattern is linear-time: quantifiers are bounded and run-based patterns are anchored
with a lookbehind so the engine cannot restart inside a run (tests/test_h4_redos.py).
Only strings are scanned for patterns: numbers in JSON are sizes, counters and ids.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import unicodedata
from bisect import bisect_right
from collections.abc import Callable, Iterable, Iterator
from functools import lru_cache
from typing import Any

MAX_DEPTH = 64
MAX_DECODE_DEPTH = 2
UNSCANNABLE = "unscannable"

# A raw hit: (value_start, value_end, kind, match_start, match_end) on the normalized text.
Hit = tuple[int, int, str, int, int]
Finder = Callable[[str], Iterable[Hit]]

# ---------------------------------------------------------------------------------------
# Normalization with a map back to the original text
# ---------------------------------------------------------------------------------------

_DASHES = frozenset("‐‑‒–—―⁃−﹘﹣－")
# Invisible in rendering: format chars, combining/enclosing marks (incl. variation selectors and
# U+034F), C1 controls; plus letters that render blank (Hangul fillers, braille blank).
_DROP_CATEGORIES = frozenset({"Cf", "Mn", "Me", "Cc"})
_BLANK_LETTERS = frozenset("ᅟᅠㅤﾠ⠀")
_SPECIAL_RE = re.compile(
    r"[^\x00-\x7f]|(?:%[0-9A-Fa-f]{2})+|&#[0-9]{1,7};|&#[xX][0-9A-Fa-f]{1,6};"
    r"|&(?:lt|gt|amp|quot|apos|colon|num|sol|nbsp);|\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}"
)
_ENTITIES = {
    "lt": "<",
    "gt": ">",
    "amp": "&",
    "quot": '"',
    "apos": "'",
    "colon": ":",
    "num": "#",
    "sol": "/",
    "nbsp": " ",
}


@lru_cache(maxsize=8192)
def _fold_char(ch: str) -> str:
    if ch < "\x80":
        return ch
    if ch in _DASHES:
        return "-"
    cat = unicodedata.category(ch)
    if cat in _DROP_CATEGORIES or ch in _BLANK_LETTERS:
        return ""
    if ch.isspace():
        return " "
    dec = unicodedata.decimal(ch, None)
    if dec is not None:
        return str(dec)
    nfkd = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
    if nfkd and nfkd.isascii():
        return nfkd
    return unicodedata.normalize("NFKC", ch)


def _fold(text: str) -> str:
    return "".join(_fold_char(c) for c in text)


def _decode_unit(tok: str) -> str:
    if tok[0] == "%":
        raw = bytes(int(tok[i + 1 : i + 3], 16) for i in range(0, len(tok), 3))
        return _fold(raw.decode("utf-8", errors="replace"))
    if tok.startswith("&#"):
        num = int(tok[3:-1], 16) if tok[2] in "xX" else int(tok[2:-1])
        return _fold(chr(num)) if 0 < num <= 0x10FFFF and not 0xD800 <= num <= 0xDFFF else ""
    if tok[0] == "&":
        return _ENTITIES[tok[1:-1]]
    if tok.startswith(("\\u", "\\x")):
        num = int(tok[2:], 16)
        return _fold(chr(num)) if not 0xD800 <= num <= 0xDFFF else ""
    return _fold_char(tok)


class Normalized:
    """The normalized view of a string plus a map from view offsets to original offsets."""

    __slots__ = ("text", "_starts", "_segs")

    def __init__(self, original: str):
        if _SPECIAL_RE.search(original) is None:
            self.text, self._starts, self._segs = original, None, None
            return
        parts: list[str] = []
        starts: list[int] = []
        segs: list[tuple[int, int, int, bool]] = []  # (norm_start, orig_start, orig_end, identity)
        pos = npos = 0
        for m in _SPECIAL_RE.finditer(original):
            if m.start() > pos:
                starts.append(npos)
                segs.append((npos, pos, m.start(), True))
                parts.append(original[pos : m.start()])
                npos += m.start() - pos
            out = _decode_unit(m.group(0))
            if out:
                starts.append(npos)
                segs.append((npos, m.start(), m.end(), False))
                parts.append(out)
                npos += len(out)
            pos = m.end()
        if pos < len(original):
            starts.append(npos)
            segs.append((npos, pos, len(original), True))
            parts.append(original[pos:])
        self.text, self._starts, self._segs = "".join(parts), starts, segs

    def to_original(self, start: int, end: int) -> tuple[int, int]:
        if self._segs is None or self._starts is None:
            return start, end
        ns, os_, oe, ident = self._segs[bisect_right(self._starts, start) - 1]
        o_start = os_ + (start - ns) if ident else os_
        ns, os_, oe, ident = self._segs[bisect_right(self._starts, end - 1) - 1]
        o_end = os_ + (end - ns) if ident else oe
        return o_start, o_end


# ---------------------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------------------

_I = re.IGNORECASE
_NOT_LETTER_BEFORE = (
    r"(?<![^\W_])"  # no letter or digit before a label ("patient_dob" ok, "S4MBI1" not)
)
_NOT_LETTER_AFTER = r"(?![^\W\d_])"
_SEP = r"""["'\s+]{0,4}(?:[:#=\-]{1,2})?["'\s+]{0,4}"""
_W = r"[\s_\-]{0,2}"  # word gap inside a label
_NUM = rf"(?:{_W}(?:number|numero|num|nbr|no\.?|n|#|id))?"


def _labelled(label: str, value: str, unspaced: str = "") -> re.Pattern[str]:
    """label (Latin/Cyrillic, needs non-letter boundaries) or unspaced (CJK/Hangul, no word
    boundaries in those scripts), then the separator, then the value as group "v"."""
    alt = rf"|(?:{unspaced})" if unspaced else ""
    return re.compile(
        rf"(?:{_NOT_LETTER_BEFORE}(?:{label}){_NOT_LETTER_AFTER}{alt}){_SEP}(?P<v>{value})", _I
    )


_SSN_VALUE = (
    r"(?!000|666|9[0-9]{2})[0-9]{3}[\s.\-]{0,2}(?!00)[0-9]{2}[\s.\-]{0,2}(?!0000)[0-9]{4}(?![0-9])"
)
_SSN_LABELLED = _labelled(
    rf"ssn|ss{_W}(?:#|no\.?|num(?:ber)?)|soc(?:ial)?\.?{_W}sec(?:urity)?\.?(?:{_W}(?:number|num|nbr|no\.?|#))?"
    rf"|(?:numero{_W}de{_W})?seguro{_W}social",
    _SSN_VALUE,
)
_SSN_BARE = re.compile(
    r"(?<![0-9A-Za-z\-])(?<![0-9]\.)(?!000|666|9[0-9]{2})[0-9]{3}(?P<s>[\-. ])(?!00)[0-9]{2}(?P=s)"
    r"(?!0000)[0-9]{4}(?![0-9\-]|\.[0-9])"
)
_A = "[AC-HJKMNP-RT-Y]"
_AN = "[AC-HJKMNP-RT-Y0-9]"
_MBI = re.compile(
    rf"(?<![A-Za-z0-9\-])[1-9]{_A}{_AN}[0-9]-?{_A}{_AN}[0-9]-?{_A}{_A}[0-9]{{2}}(?![A-Za-z0-9\-])",
    _I,
)
_MBI_LABELLED = _labelled(
    rf"medicare(?:{_W}(?:id|no\.?|num(?:ber)?|#|beneficiary(?:{_W}(?:id|identifier))?))?|mbi|hicn"
    rf"|beneficiary{_W}(?:id|identifier)",
    r"(?=[0-9A-Z\-]{0,16}[0-9])[0-9A-Z](?:[0-9A-Z]|-(?=[0-9A-Z])){8,13}(?![0-9A-Z])",
)
_MRN = _labelled(
    rf"mrn|mr\s{{0,2}}(?:#|no\.?|num(?:ber)?)|med(?:ical)?\.?{_W}rec(?:ord)?s?\.?{_NUM}"
    rf"|patient{_W}(?:id|no\.?|num(?:ber)?|#)|pt\.?{_W}(?:id|#)|chart{_W}(?:#|no\.?|num(?:ber)?|id)"
    rf"|e[mh]r{_W}(?:#|id|no\.?|num(?:ber)?)|health{_W}record{_NUM}|hospital{_W}(?:number|no\.?|#|id)"
    rf"|unit{_W}(?:number|no\.?|#)|(?:numero|no\.?|n){_W}de{_W}expediente|expediente(?:{_W}medico)?"
    rf"|historia{_W}clinica{_NUM}|registro{_W}medico|(?:numero{_W}de{_W})?dossier(?:{_W}medical)?|prontuario"
    rf"|so{_W}ho{_W}so(?:{_W}benh{_W}an)?|номер{_W}медицинской{_W}карты|медицинская{_W}карта",
    r"(?=[A-Z0-9./\-]{0,24}[0-9])[A-Z0-9](?:[A-Z0-9]|[./\-](?=[A-Z0-9])){3,24}(?:\s[0-9]{2,8}){0,3}(?![A-Z0-9])",
    r"病[历歷][号號]|病案号|등록번호|환자번호",
)
_MON = (
    r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?"
    r"|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|enero|febrero|marzo|abril|mayo|junio|julio|agosto"
    r"|sept?iembre|octubre|noviembre|diciembre|janvier|fevrier|mars|avril|mai|juin|juillet|aout|septembre"
    r"|octobre|novembre|decembre)\.?"
)
_D = r"[0-3]?[0-9](?:st|nd|rd|th)?"
_DS = r"[\s\-/.,]{0,3}"
_DATE = (
    r"(?:[0-9]{1,4}\s{0,2}[/.\-]\s{0,2}[0-9]{1,2}\s{0,2}[/.\-]\s{0,2}[0-9]{2,4}(?![0-9])"
    r"|[0-9]{8}(?![0-9])"
    rf"|{_D}(?:\s{{1,2}}(?:of|de)\s{{1,2}}|{_DS}){_MON}(?:\s{{1,2}}de\s{{1,2}}|{_DS})[0-9]{{2,4}}(?![0-9])"
    rf"|{_MON}{_DS}{_D}{_DS}[0-9]{{2,4}}(?![0-9])"
    rf"|[0-9]{{4}}{_DS}{_MON}{_DS}[0-3]?[0-9](?![0-9])"
    r"|[0-9]{4}\s?年\s?[0-9]{1,2}\s?月\s?[0-9]{1,2}\s?日?)"
    r"(?:[T ][0-9]{1,2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,9})?)?(?:Z|[+\-][0-9]{2}:?[0-9]{2})?)?"
)
_DOB = _labelled(
    rf"dob|d\.?\s?o\.?\s?b\.?|date{_W}of{_W}birth|birth{_W}date|birthday|b{_W}date|born(?:\s{{1,2}}on)?"
    rf"|fecha\s{{1,2}}de\s{{1,2}}nac(?:imiento|\.)?|f\.?\s?nac\.?|fdn|nacid[oa](?:\s{{1,2}}el)?"
    rf"|date\s{{1,2}}de\s{{1,2}}naissance|nee?\s{{1,2}}le|data\s{{1,2}}de\s{{1,2}}nascimento|ngay\s{{1,2}}sinh"
    rf"|дата\s{{1,2}}рождения|petsa\s{{1,2}}ng\s{{1,2}}kapanganakan",
    _DATE,
    r"出生日期|出生年月日|생년월일",
)
_CARD = re.compile(
    r"(?<![0-9A-Za-z\-])(?<![0-9][.,])[0-9](?:[ \-.]{0,2}[0-9]){12,18}(?![0-9A-Za-z]|[\-.,][0-9])"
)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,8}"
    r"\.[A-Za-z]{2,24}(?![A-Za-z0-9\-])"
)
_PHONE = re.compile(
    r"(?<![\w\-])(?:\+?1[\s.\-]?)?\(?[2-9][0-9]{2}\)?[\s.\-]?[2-9][0-9]{2}[\s.\-]?[0-9]{4}(?![\w\-])"
)
_B64_RUN = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/_\-]{16,}={0,2}(?![A-Za-z0-9+/=_\-])")

PATTERNS: dict[str, re.Pattern[str]] = {
    "ssn_labelled": _SSN_LABELLED,
    "ssn_bare": _SSN_BARE,
    "mbi": _MBI,
    "mbi_labelled": _MBI_LABELLED,
    "mrn": _MRN,
    "dob": _DOB,
    "card": _CARD,
    "email": _EMAIL,
    "phone": _PHONE,
    "base64_run": _B64_RUN,
    "special": _SPECIAL_RE,
}


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
    return 16 <= n <= 19 and (digits.startswith(("6011", "65")) or 644 <= int(digits[:3]) <= 649)


def _card_ok(m: re.Match[str]) -> bool:
    digits = re.sub(r"[^0-9]", "", m.group(0))
    return 13 <= len(digits) <= 19 and _card_brand_ok(digits) and _luhn_ok(digits)


def regex_finder(
    kind: str, rx: re.Pattern[str], check: Callable[[re.Match[str]], bool] | None = None
) -> Finder:
    """A finder yielding the "v" group span (or the whole match) for each match of rx."""
    has_v = "v" in rx.groupindex

    def find(text: str) -> Iterator[Hit]:
        for m in rx.finditer(text):
            if check is not None and not check(m):
                continue
            vs, ve = m.span("v") if has_v and m.group("v") is not None else m.span()
            if ve > vs:
                yield vs, ve, kind, m.start(), m.end()

    return find


_PHI_FINDERS: list[Finder] = [
    regex_finder("ssn", _SSN_LABELLED),
    regex_finder("ssn", _SSN_BARE),
    regex_finder("mbi", _MBI),
    regex_finder("mbi", _MBI_LABELLED),
    regex_finder("mrn", _MRN),
    regex_finder("dob", _DOB),
    regex_finder("card", _CARD, _card_ok),
]
_CONTACT_FINDERS: list[Finder] = [regex_finder("email", _EMAIL), regex_finder("phone", _PHONE)]


def _contact_enabled() -> bool:
    return os.environ.get("MCP_PHI_CONTACT", "0").lower() in ("1", "true", "yes")


def phi_finders() -> list[Finder]:
    return _PHI_FINDERS + _CONTACT_FINDERS if _contact_enabled() else list(_PHI_FINDERS)


# ---------------------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------------------


def _decode_b64(run: str) -> str | None:
    core = run.rstrip("=")
    if len(core) % 4 == 1:
        return None
    padded = core + "=" * (-len(core) % 4)
    try:
        raw = base64.b64decode(padded.replace("-", "+").replace("_", "/"), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return text if text and printable >= 0.9 * len(text) else None


def _hits(text: str, finders: list[Finder], depth: int) -> list[Hit]:
    hits: list[Hit] = []
    for find in finders:
        hits.extend(find(text))
    if depth < MAX_DECODE_DEPTH:
        for m in _B64_RUN.finditer(text):
            decoded = _decode_b64(m.group(0))
            if decoded is None:
                continue
            inner = find_spans(decoded, finders, depth + 1)
            if inner:
                hits.append((m.start(), m.end(), inner[0][2], m.start(), m.end()))
    return hits


def _merge(spans: Iterable[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    merged: list[tuple[int, int, str]] = []
    for s, e, kind in sorted(spans, key=lambda x: (x[0], -x[1])):
        if merged and s < merged[-1][1]:
            ps, pe, pk = merged[-1]
            merged[-1] = (ps, max(pe, e), pk)
        else:
            merged.append((s, e, kind))
    return merged


def find_spans(text: str, finders: list[Finder], _depth: int = 0) -> list[tuple[int, int, str]]:
    """Merged (start, end, kind) spans in ORIGINAL text coordinates, sorted by start."""
    norm = Normalized(text)
    hits = _hits(norm.text, finders, _depth)
    return _merge((*norm.to_original(vs, ve), kind) for vs, ve, kind, _, _ in hits)


def token(kind: str) -> str:
    return "[REDACTED]" if kind == "secret" else f"[REDACTED {kind}]"


def apply_spans(text: str, spans: list[tuple[int, int, str]]) -> str:
    if not spans:
        return text
    out: list[str] = []
    pos = 0
    for s, e, kind in spans:
        out.append(text[pos:s])
        out.append(token(kind))
        pos = e
    out.append(text[pos:])
    return "".join(out)


def cross_hits(pieces: list[str], finders: list[Finder]) -> dict[int, str]:
    """Indices of sibling values that form a match only together ({"label": "SSN", "value": "..."}).

    The pieces are joined with ": " (which lets a label in one value reach the value in the
    next, but stops digit runs from fusing across values); a hit counts when its full match
    crosses a piece boundary, and the pieces under its value span are reported.
    """
    if len(pieces) < 2:
        return {}
    norms = [Normalized(p).text for p in pieces]
    bounds: list[int] = []
    pos = 0
    for n in norms:
        bounds.append(pos)
        pos += len(n) + 2
    joined = ": ".join(norms)

    def piece_at(offset: int) -> int:
        return bisect_right(bounds, offset) - 1

    found: dict[int, str] = {}
    for vs, ve, kind, ms, me in _hits(joined, finders, MAX_DECODE_DEPTH):
        if piece_at(ms) == piece_at(me - 1):
            continue
        for i in range(piece_at(vs), piece_at(ve - 1) + 1):
            found.setdefault(i, kind)
    return found


# ---------------------------------------------------------------------------------------
# PHI-named keys
# ---------------------------------------------------------------------------------------

_PHI_KEY_RES = [
    (
        "ssn",
        r"ssn|ss_?(?:no|num|number)|social_?sec(?:urity)?(?:_?(?:no|num|number))?|soc_?sec|seguro_?social",
    ),
    ("mbi", r"mbi|hicn|medicare(?:_?(?:id|no|num|number|beneficiary(?:_?id)?))?|beneficiary_?id"),
    (
        "mrn",
        r"mrn|mr_?(?:no|num|number)|med_?rec(?:ord)?s?(?:_?(?:no|num|number|id))?"
        r"|medical_?records?(?:_?(?:no|num|number|id))?|patient_?(?:id|no|num|number)"
        r"|chart_?(?:no|num|number|id)|expediente|historia_?clinica|prontuario",
    ),
    (
        "dob",
        r"dob|date_?of_?birth|birth_?date|birthday|b_?date|fecha_?(?:de_?)?nacimiento"
        r"|date_?de_?naissance|data_?de_?nascimento",
    ),
    (
        "card",
        r"(?:credit_?)?card_?(?:no|num|number)|cc_?(?:no|num|number)|credit_?card|pan_?number",
    ),
]
PHI_KEY_RE = re.compile(
    "|".join(rf"(?P<{kind}>(?:^|_)(?:{rx})(?:_|$))" for kind, rx in _PHI_KEY_RES)
)
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def normalize_key(key: str) -> str:
    folded = _fold(str(key))
    return _NON_ALNUM_RE.sub("_", _CAMEL_RE.sub("_", folded).lower()).strip("_")


def phi_key_kind(key: Any) -> str | None:
    m = PHI_KEY_RE.search(normalize_key(str(key)))
    return m.lastgroup if m else None


def _has_content(value: Any) -> bool:
    return value is not None and value != "" and value is not False and value != [] and value != {}


# ---------------------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------------------


def find_phi_in_text(text: str) -> str | None:
    spans = find_spans(text, phi_finders())
    return spans[0][2] if spans else None


def redact_phi(text: str) -> str:
    """Replace every PHI match with "[REDACTED <type>]"."""
    return apply_spans(text, find_spans(text, phi_finders()))


def scalar_text(value: Any) -> str | None:
    """The text a sibling scalar contributes to cross-value scanning (no bools/floats/None)."""
    if isinstance(value, str):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return None


def detect_phi(value: Any, _depth: int = 0) -> str | None:
    """The first PHI type in value (strings, dict keys and values, PHI-named keys, values
    split across siblings), or "unscannable" for input too deep to scan. None = clean."""
    if _depth > MAX_DEPTH:
        return UNSCANNABLE
    if isinstance(value, str):
        return find_phi_in_text(value)
    if isinstance(value, (bytes, bytearray)):
        return find_phi_in_text(bytes(value).decode("utf-8", errors="replace"))
    if value is None or isinstance(value, (bool, int, float)):
        return None
    if isinstance(value, dict):
        items = list(value.items())
        for key, item in items:
            kind = phi_key_kind(key) if _has_content(item) else None
            found = kind or detect_phi(str(key), _depth + 1) or detect_phi(item, _depth + 1)
            if found:
                return found
        return _cross_kind([v for _, v in items])
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        for item in items:
            found = detect_phi(item, _depth + 1)
            if found:
                return found
        return _cross_kind(items)
    return find_phi_in_text(str(value))


def _cross_kind(items: list[Any]) -> str | None:
    texts = [t for t in (scalar_text(v) for v in items) if t is not None]
    hits = cross_hits(texts, phi_finders())
    return next(iter(hits.values()), None)
