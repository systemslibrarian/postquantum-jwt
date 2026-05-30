# Changelog

All notable changes to PostQuantum.Jwt are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches `1.0.0`. Preview releases (`0.x`) may break the API between
versions.

## [Unreleased]

_No changes yet._

## [0.2.0-preview.1] — 2026-05-30

A **quality and trust** release. No new public APIs — the focus is making the
existing surface trustworthy and the docs accurate. Backwards-compatible at the
source level with `0.1.0-preview.1` for any consumer that was already using it.

### Changed

- **Build is now zero warnings.** Tightened five private helper signatures in
  `PqJwtValidator` from `IReadOnlyDictionary<…>` to the concrete
  `Dictionary<…>` to clear CA1859; public surface is unchanged
  (`PqJwtValidationResult.Claims` remains `IReadOnlyDictionary`).
- **`EnablePackageValidation`** is now on in the library `.csproj`, so future
  versions are checked for accidental API breaks before publish.
- **`LICENSE` and `CHANGELOG.md`** are now packed alongside `README.md` inside
  the `.nupkg` so consumers see them in the nuget.org package details.
- **CI/release workflows** updated to action versions on Node.js 24
  (`actions/checkout@v5`, `actions/setup-dotnet@v5`,
  `actions/upload-artifact@v5`, `actions/download-artifact@v5`).

### Security hardening

- **Encrypted tokens now require `cty: JWT`** on the outer header. The builder
  always emits it; the validator now refuses encrypted tokens that don't
  declare it. Closes the "structurally unexpected nested content" gap an
  external reviewer flagged.
- **`PqJwtValidator` constructor rejects a negative `ClockSkew`** with
  `ArgumentOutOfRangeException`, so time-validation behavior is never harder
  to reason about than the documented contract.
- **Decrypted plaintext buffer is zeroed** after UTF-8 decoding, alongside the
  shared secret. The resulting `string` still lives in managed memory beyond
  our control, but the intermediate byte buffer no longer does.
- **Malformed X-Wing public keys surface as `PqJwtException`.** A
  length-correct but structurally invalid ML-KEM-768 encapsulation key inside
  a public key used to leak `CryptographicException` from the BCL during
  encryption; it now becomes a clear `PqJwtException` with an explanatory
  message, locked in by a test.

### Documentation

- **README rewritten**: 60-second tour up front, a "What's new in
  0.2.0-preview.1" section, an explicit comparison vs.
  `System.IdentityModel.Tokens.Jwt`, and a new "Operational tradeoffs" section
  covering token size, when to encrypt, replay protection in clusters, and what
  "preview" means in practice.
- **SECURITY.md** updated to reflect the broader test coverage and call out
  the specific fail-closed paths now locked by tests.
- **KNOWN-GAPS.md** reviewed for accuracy under 0.2.
- **`docs/RELEASE.md`** added — a short, honest release checklist describing
  what CI enforces, what humans review, and which provenance signals each
  release carries (and which are still missing).

### CI / release hygiene

- **`scripts/check-version-sync.sh`** asserts that the version is identical
  across `.csproj`, both README install snippets, and the CHANGELOG heading.
  Runs as a separate CI job, and as a step in the release workflow.
- **Windows CI lane is now PQ-required.** It still tests the full suite, but
  fails the run if any test reports skipped — proving the ML-KEM / ML-DSA /
  X-Wing paths actually executed in CI rather than relying on local
  verification alone. The Linux lane stays portability-only.
- **SHA-256 transparency.** The release workflow writes a
  `SHA256SUMS.txt` alongside the `.nupkg` and `.snupkg` and uploads it as a
  workflow artifact.
- **GitHub build-provenance attestations.** The release workflow now emits a
  signed attestation for the `.nupkg` via
  `actions/attest-build-provenance@v3`. Anyone can verify with
  `gh attestation verify <nupkg> --repo systemslibrarian/postquantum-jwt`.

### Added

- **Test suite expanded from 27 → 56 tests** (more than doubled). New
  fail-closed locks include:
  - `nbf` in the future is rejected; `nbf` within the 60s clock skew is
    accepted.
  - `exp` within the 60s clock skew is accepted (the skew window actually
    works, on both sides).
  - Multi-audience tokens: array `aud` claim with a matching entry passes,
    without a matching entry fails.
  - `alg: none` substitution in the header is rejected before any signature
    verification runs.
  - Header missing the `alg` field is rejected.
  - Header that is not valid JSON is rejected.
  - Payload that is a JSON array (not an object) is rejected, even with a
    valid signature over it.
  - Encrypted tokens advertising the wrong content-encryption (`A128GCM`) are
    rejected.
  - Decrypting an encrypted token with a different recipient's private key is
    rejected with an authentication-tag-mismatch error.
  - Tampering with the AES-GCM ciphertext segment is rejected.
  - Replay protection applies to encrypted tokens, not just signed-only ones.
  - Custom JSON-valued claims (arrays, ints, bools) round-trip through
    `WithClaim`.
  - `WithClaim(name, null)` removes a previously set claim.
  - `XWingPrivateKey` throws `ObjectDisposedException` after `Dispose()`; the
    double-dispose case is safe; `Export()` round-trips byte-for-byte through
    `Import()`.
  - `XWingPrivateKey.ImportSeed` rejects seeds of any length other than 32 bytes.
  - Empty token strings, four-segment tokens, signing with an ML-DSA-44 key,
    non-positive lifetimes, and empty `kid` values are all refused at the
    earliest possible point.
  - Encrypted tokens whose outer header omits `cty` or carries a non-`JWT`
    `cty` are rejected.
  - Length-correct but structurally invalid X-Wing public keys surface as
    `PqJwtException`, not as a leaking `CryptographicException`.
  - `InMemoryReplayCache` registers each unique `jti` **exactly once** under
    concurrent load — a parallel-stress test asserts the contract holds.

### Fixed

- **`SECURITY.md` combiner formula.** The prose had the X-Wing label first; the
  code and the IETF draft put it **last**. The text now matches the
  implementation (`SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)`).

### Documentation

- **README rewritten**: 60-second tour up front, a "What's new in
  0.2.0-preview.1" section, a direct comparison vs.
  `System.IdentityModel.Tokens.Jwt` with explicit "use it / use this" guidance.
- **SECURITY.md** updated to reflect the broader test coverage and to call out
  which fail-closed paths are now explicitly locked by tests.
- **KNOWN-GAPS.md** reviewed for accuracy under 0.2.

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

[Unreleased]: https://github.com/systemslibrarian/postquantum-jwt/compare/v0.2.0-preview.1...HEAD
[0.2.0-preview.1]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v0.1.0-preview.1

---

*To God be the glory — 1 Corinthians 10:31.*
