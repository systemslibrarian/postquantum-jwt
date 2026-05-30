# ADR 0001 — Algorithm agility in v0.1

- **Status:** Accepted
- **Date:** 2026-05-30
- **Context version:** `0.1.0-preview.1`

## Context

JOSE/JWT historically supports many algorithms negotiated through the `alg`
header. That flexibility is also the source of some of the format's worst
vulnerabilities — `alg: none`, RS256↔HS256 confusion, and downgrade attacks —
all of which stem from letting the *token* tell the verifier how to verify it.

PostQuantum.Jwt currently supports exactly one suite:

| Role               | Algorithm   |
|--------------------|-------------|
| Signature          | ML-DSA-65   |
| KEM                | X-Wing (X25519 + ML-KEM-768) |
| Content encryption | AES-256-GCM |

The question: should v0.1 add algorithm agility (e.g. ML-DSA-44/87,
ML-KEM-512/1024, other content ciphers, a negotiable `alg`)?

## Decision

**No. v0.1 ships a single, fixed algorithm suite.** The validator accepts only
the exact identifiers above; anything else — including `none` — is rejected
before any cryptography runs.

## Rationale

- **Security first.** A single suite eliminates downgrade and algorithm-confusion
  attacks by construction. The verifier never trusts the token's `alg` to choose
  a weaker path; it only confirms the expected one.
- **Honest scope.** The project's discipline is "no speculative features." We
  have no concrete consumer asking for other parameter sets yet, and ML-DSA-65 /
  ML-KEM-768 (NIST category 3) is a sound default.
- **Smaller attack and test surface.** One suite means the KATs, fail-closed
  tests, and wire format stay tractable and fully covered.
- **Agility ≠ negotiation.** When agility *is* added, it should be a deliberate,
  versioned, allow-listed mechanism — never open-ended negotiation driven by the
  token. The fixed suite today is forward-compatible with that model.

## Consequences

- Tokens are not interoperable with other parameter sets; consumers must use the
  same suite. This is already documented in `README.md` and `KNOWN-GAPS.md`.
- `kid`-based key resolution (added in this release) handles *key rotation*
  within the suite — the most common real need — without introducing algorithm
  negotiation.
- A future ADR will revisit agility if a concrete requirement appears (e.g. a
  higher-assurance category-5 suite). Any such change will be explicit,
  allow-listed, and fail-closed by default.

---

*To God be the glory — 1 Corinthians 10:31.*
