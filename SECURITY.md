# Security Policy

PostQuantum.Jwt is a **production-oriented preview** (`1.0.0-preview.N`) for
**controlled issuer/verifier systems** — environments where the same team owns
both token issuing and token validation. "Production-oriented" describes the
hardened defaults (strict validation, fail-closed behavior, replay and
key-rotation support), **not** an audit sign-off: the construction has **not**
been independently audited, and this is **not** a drop-in replacement for
OAuth/OIDC/JWT middleware. The leading `1.0` denotes the maturity of the design
and a stable public API/wire format across the `preview.*` series; the
`preview.N` suffix marks the **pending independent audit**, not expected API
churn (a security review could still force a change before the final `1.0.0`).
This document states the security model honestly so you can make an informed
decision before relying on it.

## Supported versions

| Version             | Supported           |
|---------------------|---------------------|
| `1.0.0-preview.4`+  | ✅ (latest preview)  |
| `1.0.0-preview.3`   | ❌ (superseded)      |
| `0.3.0-preview.*`   | ❌ (superseded)      |
| `0.2.0-preview.*`   | ❌ (superseded)      |
| `0.1.0-preview.*`   | ❌ (superseded)      |
| anything older      | ❌                  |

During the `1.0.0-preview.*` series only the most recent preview receives fixes.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for an
exploitable flaw.

- Use GitHub's **"Report a vulnerability"** (Security → Advisories) on the
  repository, **or**
- email the maintainer listed on the GitHub profile.

Please include a description, affected version, and a reproduction if possible.
We aim to acknowledge within **5 business days**. As an unfunded preview
project, timelines are best-effort and stated honestly rather than promised.

## Threat model

**Goals**

- **Token integrity & authenticity** via ML-DSA-65 signatures (FIPS 204).
- **Confidentiality** (optional) via X-Wing key agreement + AES-256-GCM, where
  the AES key is the X-Wing shared secret.
- **Hybrid resilience.** Confidentiality holds unless **both** X25519 and
  ML-KEM-768 are broken. This protects against both a future quantum adversary
  and an undiscovered weakness in the (newer) post-quantum primitive.
- **Fail-closed behavior.** Every validation failure raises an exception. There
  is no unsigned path, no `alg: none`, and no algorithm downgrade.

**Non-goals / out of scope**

- **Key management & storage.** Generating, protecting, rotating, and
  distributing keys is the caller's responsibility. The library supports
  `kid`-based key selection for rotation (`SignatureKeyResolver`) but does not
  store keys or fetch them remotely.
- **Replay protection enforcement.** The library *supports* replay defense via
  `IPqJwtReplayCache` (with a bundled single-process `InMemoryReplayCache`) and
  will fail closed at validator construction when
  `RequireReplayProtection = true`. But with no cache configured, `jti` is
  carried and not enforced — providing and operating a suitable (distributed)
  cache is the application's job.
- **Side-channel resistance beyond the underlying primitives.** We rely on the
  constant-time properties of the .NET BCL and BouncyCastle; we add no
  guarantees of our own.
- **Standards interoperability.** `ML-DSA-65` (RFC 9964) and `A256GCM`
  (RFC 7518) are registered JOSE identifiers, but the `X-Wing` key-management
  profile that combines them here is **not** a standardized JOSE/JWE profile.
  Tokens are not meant to validate or decrypt in generic JWT/JWE libraries.
- **OAuth / OIDC.** This is not a replacement for OAuth/OpenID Connect or for
  ASP.NET Core's JWT bearer middleware.
- **Application authorization.** Authenticating a token is not authorizing a
  request; enforcing scopes/roles/policies is the application's job.

**Threats considered** (the validator is built to reject these — see the
fail-closed test suite below)

- Token tampering (header, payload, or signature bytes modified).
- Signature forgery without the signing private key.
- Algorithm confusion, `alg: none`, missing `alg`, and unknown/unexpected `alg`.
- Expired tokens, not-yet-valid (`nbf`) tokens beyond the allowed skew, and
  missing `exp`.
- Wrong issuer / wrong audience.
- Replay of a previously seen `jti` (when a replay cache is configured).
- Modified ciphertext, authentication tag, AAD, or protected header on encrypted
  tokens; decryption with the wrong recipient key.
- Malformed, truncated, or wrong-segment-count token input.

**Threats not solved by the library alone** (your deployment must address these)

- Compromise of the signing private key, or of the issuing/validating server.
- Weak application-level authorization logic.
- A missing or misconfigured replay cache (e.g. a single-process cache used
  across multiple nodes).
- Absence of TLS, poor secret storage, insider threats, or supply-chain
  compromise.
- Client-side risks (XSS/CSRF, insecure token storage in the browser).

**Required production controls** (for a controlled issuer/verifier deployment)

- TLS everywhere; never transmit tokens over plaintext channels.
- Strong key storage (OS key store, cloud KMS, or vault), private keys encrypted
  at rest and never committed to source control.
- Scheduled key rotation, with old verification keys retained only for the
  longest accepted token lifetime; rotate immediately on suspected compromise.
- Issuer and audience validation enabled; short token lifetimes.
- A distributed `IPqJwtReplayCache` whenever more than one node validates tokens,
  with `RequireReplayProtection = true` so a missing cache fails at startup.
- Logs that never contain raw tokens, private keys, shared secrets, or decrypted
  sensitive claims.
- Dependency scanning and a vulnerability-disclosure process (below).

See [`samples/HARDENING-CHECKLIST.md`](samples/HARDENING-CHECKLIST.md) for a
copy-pasteable production-readiness checklist and
[`samples/SECURE-USAGE.md`](samples/SECURE-USAGE.md) for the architecture around
the token.

## Cryptographic construction

| Role                | Algorithm     | Source              |
|---------------------|---------------|---------------------|
| Signature           | ML-DSA-65     | .NET BCL (`MLDsa`)  |
| KEM (PQ half)       | ML-KEM-768    | .NET BCL (`MLKem`)  |
| KEM (classical half)| X25519        | BouncyCastle        |
| KEM combiner        | SHA3-256      | BouncyCastle        |
| Content encryption  | AES-256-GCM   | .NET BCL (`AesGcm`) |

**X-Wing combiner.** The 32-byte shared secret is

```
SHA3-256( ss_ML-KEM || ss_X25519 || ct_X25519 || pk_X25519 || label )
```

where `label` is the six bytes `0x5C 0x2E 0x2F 0x2F 0x5E 0x5C` (`\.//^\`)
concatenated **last**, per `draft-connolly-cfrg-xwing-kem`. This shared secret
is used directly as the AES-256-GCM key. The JWE protected header is bound as
AES-GCM additional authenticated data (AAD).

## Dependency rationale

The **only** third-party dependency is **BouncyCastle.Cryptography**, used
exclusively for:

1. **X25519** — the classical half of X-Wing, which the .NET BCL does not ship.
2. **SHA3-256** — the X-Wing combiner hash, used via BouncyCastle for
   cross-platform consistency.

We deliberately did **not** hand-roll X25519. Rolling your own elliptic-curve
arithmetic is exactly the kind of risk this project exists to avoid. ML-KEM-768
and ML-DSA-65 use the native, FIPS-validated BCL implementations.

## Telemetry and data handling

The library performs **no logging and no network I/O** of its own, and collects
no telemetry. The only signal it emits is an opt-in metric (the
`pqjwt.validations` counter on the `System.Diagnostics.Metrics` meter
`PostQuantum.Jwt`); nothing is recorded unless *you* attach a meter listener.

That metric is designed to be safe to export: its only tags are `outcome`
(`success`/`failure`) and a coarse, closed-vocabulary `reason` derived from the
typed `PqJwtFailureReason`. It **never** includes the token, claim values, `jti`,
issuer/audience values, or any key material. Validation failures surfaced through
the optional ASP.NET Core handler log the exception (its message and reason),
never the token or key bytes — keep `Authorization`/`Cookie` headers out of your
own request logs (see `samples/SECURE-USAGE.md` §8).

## Honesty statement

This is preview cryptographic software written in the open. It has **not** been
audited. The X-Wing key-generation and decapsulation/combiner paths **are**
validated against the official known-answer vectors; the encapsulation path is
not (the native ML-KEM API is randomized — see [`KNOWN-GAPS.md`](KNOWN-GAPS.md)).
Known limitations are tracked transparently there. Until a stable `1.0.0` and an
external review, treat the lack of an independent audit as the gating concern:
this library is appropriate for controlled issuer/verifier systems whose owners
accept that risk with eyes open — not for high-risk deployments, public-facing
auth, or anywhere generic JWT/JWE interoperability is required.

The fail-closed contract is locked in by the library test suite (**119 tests**,
`dotnet test`), including
explicit checks for `alg: none` substitution, missing `alg`, header JSON
corruption, payload that is not a JSON object, wrong content-encryption
(`A128GCM` instead of `A256GCM`), tampered ciphertext, decryption with a
different recipient key, replay across encrypted tokens, and `nbf`/`exp` skew
boundaries. If a future change weakens any of these, the suite goes red.

---

*To God be the glory — 1 Corinthians 10:31.*
