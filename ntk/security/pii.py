"""PII detection and redaction for Romanian/English documents.

Checksum-validated detectors keep false positives low: a 13-digit number is only treated as a
Romanian personal numeric code (CNP) if its date, county code and control digit are valid, and an
IBAN only if it passes ISO 7064 mod-97. Redaction is applied twice: to retrieved text BEFORE it
reaches the LLM (the model never sees PII the user may not see) and to the generated answer.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import date

_CNP = re.compile(r"(?<!\d)([1-8]\d{12})(?!\d)")
_IBAN = re.compile(r"\b(RO\d{2}(?:\s?[A-Z0-9]{4}){5})\b", re.IGNORECASE)
_PHONE = re.compile(r"(?<![\d+])(?:\+40|0040|0)\s?(?:7\d{2}|[23]\d{2})[\s.-]?\d{3}[\s.-]?\d{3}(?!\d)")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")

_CNP_WEIGHTS = (2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9)
_CENTURY = {1: 1900, 2: 1900, 3: 1800, 4: 1800, 5: 2000, 6: 2000, 7: 1900, 8: 1900}


def cnp_control_digit(first12: str) -> int:
    rest = sum(int(d) * w for d, w in zip(first12, _CNP_WEIGHTS)) % 11
    return 1 if rest == 10 else rest


def is_valid_cnp(cnp: str) -> bool:
    if not re.fullmatch(r"[1-8]\d{12}", cnp):
        return False
    year = _CENTURY[int(cnp[0])] + int(cnp[1:3])
    try:
        date(year, int(cnp[3:5]), int(cnp[5:7]))
    except ValueError:
        return False
    county = int(cnp[7:9])
    if not (1 <= county <= 52 or county in (70, 80, 81, 82, 83)):
        return False
    return cnp_control_digit(cnp[:12]) == int(cnp[12])


def is_valid_iban(iban: str) -> bool:
    s = iban.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in rearranged)
    return int(digits) % 97 == 1


@dataclass
class Redaction:
    text: str
    counts: Counter

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def redact(text: str) -> Redaction:
    counts: Counter = Counter()

    def sub(pattern: re.Pattern, label: str, validator=None):
        nonlocal text

        def repl(m: re.Match) -> str:
            if validator and not validator(m.group(1) if m.groups() else m.group(0)):
                return m.group(0)
            counts[label] += 1
            return f"[{label} REDACTED]"

        text = pattern.sub(repl, text)

    sub(_IBAN, "IBAN", is_valid_iban)
    sub(_CNP, "CNP", is_valid_cnp)
    sub(_EMAIL, "EMAIL")
    sub(_PHONE, "PHONE")
    return Redaction(text, counts)


def find_pii(text: str) -> Counter:
    return redact(text).counts
