# PostQuantum.Jwt — Spec by Example (xUnit)

An **executable specification**. Each test name is a lesson; the body is the
smallest code that proves it. Prefer learning a library by stepping through
tests in your IDE? Start here.

```bash
cd samples/SpecByExample
dotnet test
```

Set a breakpoint in any `[RequiresPq]` test and step through it. The Attack-Mode
tests are the most instructive — watch a tampered token fail signature
verification line by line:

- `Editing_a_claim_and_reusing_the_signature_breaks_verification`
- `An_alg_none_token_is_rejected`
- `A_token_signed_by_the_wrong_key_is_rejected`
- `An_expired_token_is_rejected`
- `A_token_with_no_exp_is_rejected`
- `The_same_one_time_token_cannot_be_used_twice`

Tests **skip themselves** (not fail) on hosts without native ML-DSA/ML-KEM
(needs OpenSSL 3.5+ or recent Windows).

> This is documentation that happens to run. It is **not** the library's own
> test suite — that lives in `tests/` and is far more exhaustive.

---

*To God be the glory — 1 Corinthians 10:31.*
