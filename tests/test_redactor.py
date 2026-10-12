from fastapi.testclient import TestClient
from redactor.app import app
from redactor.detectors import redact, verhoeff_ok, verhoeff_digit, luhn_ok

c = TestClient(app)

def test_checksums():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert verhoeff_ok("23412341234" + verhoeff_digit("23412341234"))

def test_invalid_aadhaar_not_redacted():
    b = "23412341234"; bad = b + str((int(verhoeff_digit(b)) + 1) % 10)
    assert redact(f"ref {bad}")[1] == []

def test_card_with_spaces_regression():
    t, h = redact("contact 4111 1111 1111 1111 for follow-up")
    assert t == "contact [CARD] for follow-up"

def test_secrets():
    t, _ = redact("key AKIAABCDEFGHIJKLMNOP and ghp_" + "a" * 36)
    assert "[AWS_KEY]" in t and "[GITHUB_TOKEN]" in t

def test_indian_ids():
    t, _ = redact("PAN ABCPE1234F IFSC HDFC0001234 UPI ravi@okaxis phone +91 9876543210")
    assert t == "PAN [PAN] IFSC [IFSC] UPI [UPI] phone [PHONE_IN]"

def test_middleware_redacts_chat_and_keeps_json_valid():
    r = c.post("/v1/chat", json={"prompt": "email ravi@example.in card 4111111111111111"})
    assert r.status_code == 200
    body = r.json()["completion"]
    assert "ravi@example.in" not in body and "[EMAIL]" in body and "[CARD]" in body
    assert r.headers["x-redactions"] == "2"

def test_clean_response_untouched():
    r = c.get("/healthz")
    assert r.json() == {"ok": True} and r.headers["x-redactions"] == "0"

def test_mask_mode_preserves_length():
    t, _ = redact("a@b.co", mode="mask")
    assert t == "******"
