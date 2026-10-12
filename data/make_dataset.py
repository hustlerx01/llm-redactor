"""Seeded synthetic eval set: LLM-style sentences with planted PII/secrets + hard negatives. All values are fake."""
import json, pathlib, random, string, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from redactor.detectors import verhoeff_digit, verhoeff_ok, luhn_ok

rnd = random.Random(42)
def luhn_card(prefix, n=16):
    while True:
        s = prefix + "".join(rnd.choice(string.digits) for _ in range(n - len(prefix)))
        if luhn_ok(s): return s
def aadhaar():
    b = str(rnd.randint(2, 9)) + "".join(rnd.choice(string.digits) for _ in range(10)); return b + verhoeff_digit(b)
def bad_aadhaar():
    while True:
        s = str(rnd.randint(2, 9)) + "".join(rnd.choice(string.digits) for _ in range(11))
        if not verhoeff_ok(s): return s
def bad_card():
    while True:
        s = "4" + "".join(rnd.choice(string.digits) for _ in range(15))
        if not luhn_ok(s): return s
up = lambda n: "".join(rnd.choice(string.ascii_uppercase) for _ in range(n))
an = lambda n: "".join(rnd.choice(string.ascii_letters + string.digits) for _ in range(n))
names = ["ravi", "priya", "ansar", "neha", "arjun", "fatima", "rohit", "sneha"]

GEN = {
 "EMAIL": lambda: f"{rnd.choice(names)}.{rnd.randint(1,99)}@example.in",
 "PHONE_IN": lambda: rnd.choice(["+91 ", "+91-", "", "0"]) + str(rnd.randint(6, 9)) + "".join(rnd.choice(string.digits) for _ in range(9)),
 "AADHAAR": lambda: (lambda a: rnd.choice([a, f"{a[:4]} {a[4:8]} {a[8:]}"]))(aadhaar()),
 "PAN": lambda: up(3) + "P" + up(1) + str(rnd.randint(1000, 9999)) + up(1),
 "CARD": lambda: (lambda c: rnd.choice([c, " ".join(c[i:i+4] for i in range(0, 16, 4))]))(luhn_card(rnd.choice(["4", "51", "6"]))),
 "IFSC": lambda: rnd.choice(["HDFC", "SBIN", "ICIC", "UTIB"]) + "0" + "".join(rnd.choice(string.digits) for _ in range(6)),
 "UPI": lambda: f"{rnd.choice(names)}{rnd.randint(1,999)}@{rnd.choice(['okaxis','ybl','paytm','oksbi'])}",
 "IPV4": lambda: f"10.{rnd.randint(0,255)}.{rnd.randint(0,255)}.{rnd.randint(1,254)}",
 "AWS_KEY": lambda: "AKIA" + "".join(rnd.choice(string.ascii_uppercase + string.digits) for _ in range(16)),
 "GITHUB_TOKEN": lambda: "ghp_" + an(36),
 "API_KEY": lambda: "sk-" + an(40),
 "JWT": lambda: "eyJhbGciOiJIUzI1NiJ9." + an(24) + "." + an(32),
}
TPL = ["Sure, the customer's {k} is {v}.", "From the ticket: contact {v} for follow-up.", "I found this in the logs: {v}",
       "Here is the config value you asked for: {v} (store it safely).", "Record #{n}: {v}, verified."]
NEG = [lambda: f"Order ID {rnd.randint(10**11, 10**12-1)} has shipped.", lambda: f"Invalid card test value {bad_card()}.",
       lambda: f"Reference number {bad_aadhaar()} is not an Aadhaar.", lambda: f"Build v{rnd.randint(1,9)}.{rnd.randint(0,20)}.{rnd.randint(0,9)} released.",
       lambda: f"Call the toll-free line 1800-{rnd.randint(100,999)}-{rnd.randint(1000,9999)}.", lambda: "The SKU is ABCD1234EF and the batch is X9.",
       lambda: f"Timestamp {rnd.randint(1700000000, 1799999999)} in epoch seconds.", lambda: "Software version 4.12.0.1 is deprecated.",
       lambda: "Use the placeholder you@yourcompany for docs.", lambda: f"Invoice INV-{rnd.randint(100000,999999)} total ₹{rnd.randint(100,99999)}."]
rows = []
for kind, g in GEN.items():
    for _ in range(15):
        v = g(); rows.append({"text": rnd.choice(TPL).format(k=kind.lower(), v=v, n=rnd.randint(1, 999)), "entities": [{"type": kind, "value": v}]})
for _ in range(60):
    rows.append({"text": rnd.choice(NEG)(), "entities": []})
rnd.shuffle(rows)
out = pathlib.Path(__file__).with_name("eval.jsonl")
out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
print(f"wrote {len(rows)} rows")
