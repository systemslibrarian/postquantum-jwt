# Changelog

All notable changes to PostQuantum.Jwt are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches `1.0.0`. Preview releases (`0.x`) may break the API between
versions.

## [Unreleased]

_No changes yet._

## [0.1.0-preview.1] — 2026-05-30

Initial public preview.

### Added

- **`PqJwtBuilder`** — fluent builder for signed (3-part) or signed-then-encrypted
  (5-part) JWTs. Mandatory ML-DSA-65 signing; no `alg: none` path.
- **`PqJwtValidator`** — fail-closed validator. Anything wrong (bad signature,
  tampered payload, expired token, wrong audience, malformed structure) throws
  `PqJwtValidationException`. Thread-safe and reusable.
- **`PqJwtValidationParameters`** — issuer / audience / lifetime configuration,
  with strict defaults (expiration required, 60s clock skew).
- **Hybrid post-quantum cryptography**:
  - Signatures via **ML-DSA-65** (FIPS 204) on the native .NET BCL `MLDsa`
    primitive.
  - Optional encryption via **X-Wing** (X25519 + ML-KEM-768) per
    `draft-connolly-cfrg-xwing-kem`, with the 32-byte shared secret used
    directly as an AES-256-GCM key. ML-KEM-768 is the native BCL `MLKem`
    primitive; X25519 and SHA3-256 come from BouncyCastle.
  - Sign-then-encrypt construction with the JWE protected header bound as
    AES-GCM AAD.
- **`XWingPrivateKey` / `XWingPublicKey`** — hybrid KEM keys with `Generate()`,
  `ImportSeed()`, `Import()`, and `Export()`. Seed-derived key generation
  matches the spec's `expandDecapsulationKey`.
- **`IPqJwtReplayCache` + `InMemoryReplayCache`** — opt-in single-use `jti`
  enforcement. The in-memory cache is single-process; replace it for distributed
  deployments.
- **`SignatureKeyResolver`** — `kid`-based verification-key lookup for key
  rotation.
- **Known-answer tests** — the X-Wing seed-keygen and decapsulation/combiner
  paths are validated against the official IETF test vectors.

### Security

- Fail-closed by construction: every validation/decryption failure throws.
- Only one algorithm suite is accepted (ML-DSA-65, X-Wing, A256GCM); algorithm
  downgrade and `alg: none` confusion are impossible by design.
- Key material is zeroed with `CryptographicOperations.ZeroMemory` after use,
  and `XWingPrivateKey` is `IDisposable` to release the native ML-KEM handle.

### Known limitations

See [`KNOWN-GAPS.md`](KNOWN-GAPS.md). Highlights:

- **Not externally audited.** Preview software — not for production use.
- **Encapsulation path is not KAT-checked** (the native `MLKem.Encapsulate`
  is randomized and exposes no derandomized entry point). Round-trip and
  decapsulation KATs cover the rest.
- **Non-standard JOSE identifiers.** `ML-DSA-65`, `X-Wing`, `A256GCM` (over
  nested JWT) are not IANA-registered; tokens will **not** validate in generic
  JWT tooling.
- **No algorithm agility** by design — see
  [`docs/adr/0001-algorithm-agility.md`](docs/adr/0001-algorithm-agility.md).
- **Packages are not author-signed yet** (no code-signing certificate).
  nuget.org applies repository signing on push.

[Unreleased]: https://github.com/systemslibrarian/postquantum-jwt/compare/v0.1.0-preview.1...HEAD
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v0.1.0-preview.1

---

*To God be the glory — 1 Corinthians 10:31.*
