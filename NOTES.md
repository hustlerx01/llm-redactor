# Interview talking points: LLM PII/secret redactor

1. **Why output-side.** The LLM sees tickets and logs full of PII and repeats them. I *showed* it: qwen2.5 echoed an Aadhaar and a card number in a "summary". Redacting at the response boundary covers every endpoint at once, as middleware.
2. **Checksums cut false positives.** Every 12-digit number isn't an Aadhaar. Verhoeff validation, which UIDAI uses, rejects about 90% of random 12-digit strings, and Luhn does the same for cards. That's why order IDs and timestamps in my negative set produced 0 FPs.
3. **Keeping JSON valid.** Redacting raw bytes could corrupt JSON or Unicode escapes, so I parse the body, walk the string values, then re-serialise. I strip the stale `content-length` header too.
4. **The eval caught a bug.** My card regex captured a trailing space, so recall was 0.80. A test set with exact values found it, and now there's a regression test. Measuring beats eyeballing.
5. **Audit without leaking.** The log records entity *types and counts*, never values. Otherwise the redactor's log becomes the new leak.
6. **Know the limits.** No NER (names), no streaming, and IPv4 vs version strings are ambiguous. The next steps: Presidio/spaCy for names, a sliding-window streaming redactor, request-side redaction before third-party LLMs.
7. **Compliance link.** DPDP Act 2023 and OWASP LLM02 (sensitive information disclosure). The `x-redactions` header gives the SOC a metric to alert on.
