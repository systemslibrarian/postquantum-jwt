# Security Audit Findings

**1. Plaintext not zeroed on exception in `EncryptToken`**
**File:** [src/PostQuantum.Jwt/PqJwtBuilder.cs](src/PostQuantum.Jwt/PqJwtBuilder.cs#L235-L255)
**Violation:** CLAUDE.md: "Secrets: zero key material with CryptographicOperations.ZeroMemory after use".
**Proof:** 
In `EncryptToken`, `plaintext` is declared at [line 235](src/PostQuantum.Jwt/PqJwtBuilder.cs#L235) and holds sensitive JWT data. `gcm.Encrypt()` is called at [line 242](src/PostQuantum.Jwt/PqJwtBuilder.cs#L242). If encryption fails and throws an exception, execution jumps directly to the `finally` block at [line 252](src/PostQuantum.Jwt/PqJwtBuilder.cs#L252), which zeroes `sharedSecret` but misses `plaintext`. `CryptographicOperations.ZeroMemory(plaintext)` at [line 245](src/PostQuantum.Jwt/PqJwtBuilder.cs#L245) is bypassed, leaving plaintext unzeroed in memory.

**2. Missing telemetry for oversized tokens**
**File:** [src/PostQuantum.Jwt/PqJwtValidator.cs](src/PostQuantum.Jwt/PqJwtValidator.cs#L113-L118)
**Violation:** CLAUDE.md / Audit rules: "telemetry — failures emit coarse System.Diagnostics.Metrics".
**Proof:** 
At [line 113](src/PostQuantum.Jwt/PqJwtValidator.cs#L113), the oversized length check (`token.Length > MaxTokenLength`) explicitly throws a `PqJwtValidationException(PqJwtFailureReason.MalformedToken)`. This occurs *before* entering the `try` block at [line 120](src/PostQuantum.Jwt/PqJwtValidator.cs#L120). As a result, the exception escapes the `catch (PqJwtException ex)` handler at [line 136](src/PostQuantum.Jwt/PqJwtValidator.cs#L136) which invokes `RecordFailure(ex)`. Oversized adversarial tokens bypass the telemetry tracking logic entirely.

---

## Resolution (2026-06-30, pre-`1.0.0`)

Both findings were verified against the code and **fixed** before the `1.0.0`
publish. Both are low-severity hardening/consistency issues (no exploit, no wire
or API change), but both contradicted the project's stated discipline and were
worth closing before stamping a stable release.

**1. Plaintext not zeroed on exception — FIXED.** `EncryptToken`
(`PqJwtBuilder.cs`) now materialises the inner-JWS `plaintext` *before* the
`try` and zeroes it in the `finally`, alongside the X-Wing `sharedSecret`. The
success-path-only `ZeroMemory(plaintext)` was removed, so the plaintext is
zeroed on every path — including an exception out of `AesGcm.Encrypt`. (In
practice `AesGcm.Encrypt` does not throw with correctly-sized buffers, so this
is defense-in-depth on a practically-unreachable path; the fix makes the intent
exception-safe.)

**2. Oversized tokens bypass telemetry — FIXED.** The `token.Length >
MaxTokenLength` cap in `PqJwtValidator.Validate` was moved *inside* the
`try` block (still the first check, before any split/decode/verify), so the
`catch (PqJwtException ex)` records `pqjwt.validations{outcome=failure,
reason=malformed_token}` like every other fail-closed rejection. An
oversized-token flood is a DoS signal that now shows up in metrics.
Regression-locked by
`PqJwtMetricsTests.Oversized_token_rejection_increments_outcome_failure_with_malformed_token`.

Both fixes are documented in the `[1.0.0]` entry of `CHANGELOG.md`. Default test
suite green at **180 tests, 0 skipped**; Release build clean.
