# Security Policy

PostQuantum.Jwt is **preview software** (`0.x.y-preview.z`). It is not yet
suitable for production use and has not been independently audited. This
document states the security model honestly so you can make an informed
decision before relying on it.

## Supported versions

| Version             | Supported           |
|---------------------|---------------------|
| `0.2.0-preview.2`+  | ✅ (latest preview)  |
| `0.2.0-preview.1`   | ❌ (superseded)      |
| `0.1.0-preview.*`   | ❌ (superseded)      |
| anything older      | ❌                  |

During the `0.x` series only the most recent preview receives fixes.

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
  distributing keys is the caller's responsibility.
- **Replay protection.** `jti` is carried but not tracked; replay defense is the
  application's job.
- **Side-channel resistance beyond the underlying primitives.** We rely on the
  constant-time properties of the .NET BCL and BouncyCastle; we add no
  guarantees of our own.
- **Standards interoperability.** Tokens use non-IANA algorithm identifiers and
  are not meant to validate in generic JWT libraries.

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

## Honesty statement

This is preview cryptographic software written in the open. It has **not** been
audited. The X-Wing key-generation and decapsulation/combiner paths **are**
validated against the official known-answer vectors; the encapsulation path is
not (the native ML-KEM API is randomized — see [`KNOWN-GAPS.md`](KNOWN-GAPS.md)).
Known limitations are tracked transparently there. Until a 1.0 release and an
external review, treat this library as suitable for experimentation only.

The fail-closed contract is locked in by **57 tests** (`dotnet test`), including
explicit checks for `alg: none` substitution, missing `alg`, header JSON
corruption, payload that is not a JSON object, wrong content-encryption
(`A128GCM` instead of `A256GCM`), tampered ciphertext, decryption with a
different recipient key, replay across encrypted tokens, and `nbf`/`exp` skew
boundaries. If a future change weakens any of these, the suite goes red.

---

*To God be the glory — 1 Corinthians 10:31.*
