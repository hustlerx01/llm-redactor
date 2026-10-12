"""PII + secret detectors with checksum validation (Luhn for cards, Verhoeff for Aadhaar) to cut false positives."""
import re
from dataclasses import dataclass

# Verhoeff tables (UIDAI uses Verhoeff for the Aadhaar check digit)
_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
      [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],
      [4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]

def verhoeff_ok(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0

def verhoeff_digit(num: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])

def luhn_ok(num: str) -> bool:
    s, alt = 0, False
    for ch in reversed(num):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9: d -= 9
        s += d; alt = not alt
    return s % 10 == 0

@dataclass
class Rule:
    kind: str
    rx: re.Pattern
    validate: object = None

digits = lambda s: re.sub(r"\D", "", s)
RULES = [
    Rule("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----")),
    Rule("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    Rule("AWS_KEY", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    Rule("API_KEY", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    Rule("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Rule("UPI", re.compile(r"\b[a-z0-9._-]{2,}@(ok(axis|hdfcbank|icici|sbi)|ybl|paytm|upi|ibl|axl)\b", re.I)),
    Rule("CARD", re.compile(r"\b\d(?:[ -]?\d){12,18}\b"), lambda m: 13 <= len(digits(m)) <= 19 and luhn_ok(digits(m)) and not (len(digits(m)) == 12)),
    Rule("AADHAAR", re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"), lambda m: verhoeff_ok(digits(m))),
    Rule("PAN", re.compile(r"\b[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]\b")),
    Rule("IFSC", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")),
    Rule("PHONE_IN", re.compile(r"(?<![\d-])(?:\+91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?![\d-])")),
    Rule("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]

def find(text: str):
    spans = []
    for r in RULES:
        for m in r.rx.finditer(text):
            if r.validate and not r.validate(m.group(0)):
                continue
            if any(m.start() < e and s < m.end() for s, e, _ in spans):  # earlier (more specific) rule wins
                continue
            spans.append((m.start(), m.end(), r.kind))
    return sorted(spans)

def redact(text: str, mode: str = "tag"):
    spans = find(text); out, last = [], 0
    for s, e, k in spans:
        out.append(text[last:s]); out.append(f"[{k}]" if mode == "tag" else "*" * (e - s)); last = e
    out.append(text[last:])
    return "".join(out), [{"type": k, "start": s, "end": e} for s, e, k in spans]
