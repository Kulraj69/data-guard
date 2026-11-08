"""Deterministic PII/secret detection and reversible redaction.

Middleware for agent pipelines: scan text before it leaves a trust boundary
(a prompt to a model, a message between agents, a log line) and replace
sensitive values with stable placeholders. A Redactor keeps the mapping so
responses can be restored on the return path.

Rule-based detection is defense in depth, not a guarantee: it catches
well-formed patterns (cards with valid Luhn, AWS-style keys, JWTs, common
PII shapes) and will miss deliberately obfuscated or unusual formats.
"""

import re
from collections import defaultdict
from dataclasses import dataclass

# --- detectors ------------------------------------------------------------

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[\s-]?)?(?:\(\d{2,4}\)[\s-]?)?\d{3,4}[\s-]\d{3,4}(?:[\s-]\d{3,4})?(?!\w)")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b")


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


def _find_cards(text):
    for m in _CARD_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            yield m


@dataclass
class Finding:
    kind: str
    placeholder: str
    start: int
    end: int


_PATTERNS = [
    ("AWS_KEY", _AWS_KEY),
    ("JWT", _JWT),
    ("BEARER", _BEARER),
    ("EMAIL", _EMAIL),
    ("SSN", _SSN),
    ("IPV4", _IPV4),
    ("PHONE", _PHONE),
]


def scan(text: str):
    """Report raw (kind, start, end) matches without redacting."""
    findings = []
    for kind, pat in _PATTERNS:
        findings.extend((kind, m.start(), m.end()) for m in pat.finditer(text))
    findings.extend(("CARD", m.start(), m.end()) for m in _find_cards(text))
    # Longest match at each position wins overlaps (card over phone prefix).
    findings.sort(key=lambda f: (f[1], -(f[2] - f[1])))
    merged = []
    last_end = -1
    for kind, s, e in findings:
        if s >= last_end:
            merged.append((kind, s, e))
            last_end = e
    return merged


class Redactor:
    """Redacts matches to stable placeholders; can restore them later.

    Placeholders are stable per (kind, value): the same email always maps to
    [EMAIL_1] within one Redactor, so repeated mentions stay linked without
    exposing the value.
    """

    def __init__(self):
        self._maps = defaultdict(dict)      # kind -> {value: placeholder}
        self._reverse = {}                  # placeholder -> value
        self._counters = defaultdict(int)

    def _placeholder(self, kind, value):
        table = self._maps[kind]
        if value not in table:
            self._counters[kind] += 1
            ph = "[%s_%d]" % (kind, self._counters[kind])
            table[value] = ph
            self._reverse[ph] = value
        return table[value]

    def redact(self, text: str):
        """Return (redacted_text, [Finding, ...]). Idempotent."""
        findings = []
        out = []
        last = 0
        for kind, s, e in scan(text):
            value = text[s:e]
            ph = self._placeholder(kind, value)
            findings.append(Finding(kind, ph, s, e))
            out.append(text[last:s])
            out.append(ph)
            last = e
        out.append(text[last:])
        return "".join(out), findings

    def restore(self, text: str) -> str:
        """Swap placeholders back to original values."""
        for ph, value in self._reverse.items():
            text = text.replace(ph, value)
        return text
