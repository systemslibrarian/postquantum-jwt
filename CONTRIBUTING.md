# Contributing to PostQuantum.Jwt

Thank you for your interest. PostQuantum.Jwt is a **production-oriented preview**
for controlled issuer/verifier systems; it is **not** independently audited. The
bar for changes — especially security-relevant ones — is high and biased toward
honesty over polish.

## Build & test

```bash
dotnet build
dotnet test
```

The tests that exercise the native post-quantum primitives need OpenSSL 3.5+. In
the dev container, run the full suite with:

```bash
LD_LIBRARY_PATH=/opt/conda/lib dotnet test
```

A test that cannot run its crypto MUST skip with a reason (`[PqcFact]`), never
silently pass.

## Before opening a PR

1. `dotnet build` and `dotnet test` are green, with **zero warnings** (the build
   treats compiler warnings as errors).
2. Public API has XML doc comments (`GenerateDocumentationFile` is on).
3. Security-relevant changes land **with** a test that locks in the fail-closed
   behavior.

## Coding & security rules

These mirror [`CLAUDE.md`](CLAUDE.md), which is the authoritative guide:

- **Fail-closed, always.** No `alg: none`, no unsigned path, no silent downgrade,
  no "best effort" result. Every validation/decryption failure throws.
- **Do not add algorithm agility casually.** One suite (ML-DSA-65 + X-Wing +
  AES-256-GCM) unless there is a written, concrete reason. No `alg` negotiation,
  no RSA/HMAC/ECDSA, no fallback path.
- **Don't roll your own crypto.** Use the .NET BCL primitives; BouncyCastle is
  used **only** for X25519 and SHA3-256. A new third-party dependency needs a
  written justification in [`SECURITY.md`](SECURITY.md).
- **Never log or return secrets.** No raw tokens, private keys, shared secrets,
  or decrypted sensitive claims in logs, exceptions, or return values.
- **Keep the surface small.** No speculative features.
- **Be honest in docs.** Don't reintroduce overclaims — see the "language we
  intentionally avoid" list in [`KNOWN-GAPS.md`](KNOWN-GAPS.md). Do not describe
  the package as audited, production-grade, OIDC-compatible, or generically
  JWT/JWE interoperable.

## When you change behavior

- Update [`docs/SPEC.md`](docs/SPEC.md) if you change the token profile (wire
  format, header members, algorithm suite, or validation order).
- Update [`CHANGELOG.md`](CHANGELOG.md) under `Unreleased`.
- Update [`KNOWN-GAPS.md`](KNOWN-GAPS.md) if you close or open a gap.

## Reporting a vulnerability

Please **do not** open a public issue for an exploitable flaw. Use GitHub's
*Report a vulnerability* button on the repository, or the process in
[`SECURITY.md`](SECURITY.md).

---

*To God be the glory — 1 Corinthians 10:31.*
</content>
