# CLAUDE.md — PostQuantum.Jwt

Conventions and guardrails for working in this repository. Read before making
changes.

## What this is

A post-quantum **hybrid** JWT library for .NET 10. ML-DSA-65 signatures, optional
X-Wing (X25519 + ML-KEM-768) + AES-256-GCM encryption. Post-quantum primitives
come from the native .NET BCL; BouncyCastle is used **only** for X25519 and
SHA3-256.

## Engineering discipline

- **Honesty over polish.** If something is incomplete, unproven, or risky, say so
  — in code comments, `SECURITY.md`, and `KNOWN-GAPS.md`. Never overstate what
  the crypto provides. (The first draft README claimed "full compatibility with
  the standard JWT ecosystem"; that was false and was corrected. Don't reintroduce
  that kind of claim.)
- **Fail-closed, always.** Every validation/decryption failure throws. No
  `alg: none`, no unsigned path, no silent downgrade, no "best effort" result.
- **Don't roll your own crypto.** Use the BCL primitives; use BouncyCastle for
  the one gap (X25519). If you reach for hand-written curve/field arithmetic,
  stop and reconsider.
- **Native BCL first.** Prefer `System.Security.Cryptography` primitives. A new
  third-party dependency needs a written justification in `SECURITY.md`.
- **Keep the surface small.** No speculative features. One algorithm suite until
  there's a concrete reason to add agility.

## Code conventions

- **Target:** `net10.0` only.
- **Nullable** and **implicit usings** are on. `LangVersion` is `latest`.
- **Warnings:** compiler warnings are errors (`TreatWarningsAsErrors`), analyzer
  (`CAxxxx`) suggestions stay warnings (`CodeAnalysisTreatWarningsAsErrors=false`).
  Don't suppress an analyzer without a comment explaining why.
- **Public API is documented.** XML doc comments on every public member
  (`GenerateDocumentationFile` is on).
- **Deterministic builds** are enabled repo-wide; don't add nondeterminism.
- **Naming:** `PqJwt*` for the public surface; internal crypto lives in
  `PostQuantum.Jwt.Cryptography`; helpers in `PostQuantum.Jwt.Internal`.
- **Secrets:** zero key material with `CryptographicOperations.ZeroMemory` after
  use; dispose anything holding key handles.

## Layout

```
src/PostQuantum.Jwt/          library
  PqJwtBuilder / PqJwtValidator / PqJwt* …   public API
  Cryptography/               X-Wing KEM + key types (internal engine)
  Internal/                   Base64Url, JoseHeader
tests/PostQuantum.Jwt.Tests/  xUnit tests
docs/                         design notes
```

## Build & test

```bash
dotnet build
dotnet test
```

Tests touching native ML-KEM / ML-DSA skip themselves (with a reason) when the
host lacks support. **In this dev container** the native primitives need
conda's OpenSSL 3.5+, so run the full suite with:

```bash
LD_LIBRARY_PATH=/opt/conda/lib dotnet test
```

(The system `libcrypto.so.3` here predates ML-KEM; conda's does not. This is an
environment quirk, not a library requirement — the library only needs *some*
OpenSSL 3.5+.)

## Tests must stay honest

- A test that can't run its crypto should **skip with a reason** (`[PqcFact]`),
  never silently pass.
- Keep the fail-closed tests: tampered signature, tampered payload, expiry,
  missing `exp`, wrong audience, wrong key, malformed token.

## Faith statement

This project is built in gratitude to God. Documentation ends with:

> *To God be the glory — 1 Corinthians 10:31.*

Keep that footer on the README and the security docs.
