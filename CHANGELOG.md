# Changelog

All notable changes to PostQuantum.Jwt are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
from the stable `1.0.0` onward. Pre-release `1.0.0-preview.*` builds may break
the API between previews.

## [Unreleased]

## [1.0.0-preview.2] — 2026-06-02

An **additive** release. The crypto core, public algorithm surface, and
fail-closed validation behavior are **unchanged** — no new suite, no algorithm
agility. This release adds observability, a typed failure taxonomy, and the
runnable samples/templates ecosystem.

### Added

- **Validation metrics.** `PqJwtValidator` emits a `pqjwt.validations` counter on
  a `System.Diagnostics.Metrics` meter named `PostQuantum.Jwt`, tagged
  `outcome=success|failure` and, on failure, a coarse `reason`. Opt in with
  OpenTelemetry or any meter listener — no new dependency. The `reason` is a
  closed, bounded-cardinality vocabulary and **never** carries token contents,
  claim values, or key material. The meter name is stable API.
- **`PqJwtFailureReason` enum** and **`PqJwtValidationException.Reason`** property
  (plus reason-carrying constructors). Callers and the metric categorize a
  rejection from a typed value instead of parsing the exception message.
- **Runnable samples** under `samples/` (console, ASP.NET Core API, verifier,
  Blazor playground, refresh-token rotation, distributed replay cache, testing
  support, spec-by-example) with a `samples/PostQuantum.Jwt.Samples.slnx`
  solution and a CI compile gate.
- **`PostQuantum.Jwt.Templates`** `dotnet new` template package
  (`pqjwt-webapi`, `pqjwt-console`).
- **Expanded hardening docs** — `samples/SECURE-USAGE.md` and
  `samples/HARDENING-CHECKLIST.md` map common JWT attacks to the library's
  defenses and the metric `reason` that surfaces each.

### Changed

- Internal: every fail-closed throw site (including `JoseHeader` parsing) now
  carries a typed `PqJwtFailureReason`. No behavior change — control flow and
  rejection conditions are identical.

### Fixed

- **Malformed header fields no longer escape as an uncaught exception.** A header
  field that is present but not a string (e.g. `"alg": 123` or `"alg": ["none"]`)
  previously raised `InvalidOperationException`, which fell outside `Validate()`'s
  catch filter and surfaced as an unhandled error (HTTP 500). Such fields are now
  read safely and fail closed as `PqJwtValidationException`.
- **Present-but-malformed `exp` / `nbf` are now rejected, not ignored.** A time
  claim that exists but isn't an integer Unix time (a string or fractional number)
  was silently treated as absent — bypassing the not-before check and, with
  `RequireExpiration` off, making the token immortal. It now fails closed with the
  new `PqJwtFailureReason.MalformedTimeClaim`, in both lifetime validation and the
  replay-cache expiry path (so a malformed `exp` can never be cached as a
  never-expiring entry).
- **`InMemoryReplayCache` pruning is now amortized.** The expired-entry sweep ran
  on every `TryRegister`, scanning the whole dictionary — O(n) per call, an
  algorithmic-complexity DoS vector under token floods. It now runs at most once
  per interval; replay-detection correctness is unchanged.

## [1.0.0-preview.1] — 2026-06-01

A **maturity-tier bump** for the PostQuantum.* JWT stack, from
`0.3.0-preview.1` to `1.0.0-preview.1`. The crypto core and public algorithm
surface are unchanged — no new algorithm suite, no algorithm agility,
ML-DSA-65 + X-Wing + AES-256-GCM with sign-then-encrypt and RFC 7516 AAD
binding remains the only path. The 1.0 tier brings a sharper safety posture:
a `RequireReplayProtection` flag so an operator can't forget to wire a
replay cache, an internal test seam that lets the suite KAT what *can* be
made deterministic in encapsulation (with the production randomness path
still bit-identical to before, just routed through `RandomNumberGenerator`),
a 64-iteration statistical sanity check on encapsulation, and a pinned
end-to-end roundtrip corpus. The `preview.N` suffix carries the maturity
caveat, not the leading `1.0`: the cryptographic construction has **not**
been independently audited, and the non-IANA-registered identifiers mean
these tokens still do **not** interop with standard JWT tooling. See
[`KNOWN-GAPS.md`](KNOWN-GAPS.md) and the new "Read this first" disclosure at
the top of the README.

### Changed

- **Version raised to `1.0.0-preview.1`** in both `PostQuantum.Jwt` and
  `PostQuantum.Jwt.AspNetCore`. The two packages move in exact lockstep —
  `PostQuantum.Jwt.AspNetCore` continues to depend on `PostQuantum.Jwt` at
  the matching version via its `ProjectReference`, which NuGet rewrites into
  a pinned `PackageReference` at pack time. See
  [`VERSION-RECONCILIATION.md`](VERSION-RECONCILIATION.md) for the
  suite-level audit (no package in this repo advertises more maturity than
  what it depends on).
- **`PostQuantum.Jwt.AspNetCore` remains marked as superseded by
  `PostQuantum.AspNetCore`** (cleaner naming, dedicated release cadence,
  event-hook surface, hosted-service warmup, SignalR support). Tokens
  minted under either validate in the other. The legacy companion receives
  **critical fixes only**; no new features. Migration guide:
  [`postquantum-aspnetcore/docs/MIGRATION.md`](https://github.com/systemslibrarian/postquantum-aspnetcore/blob/main/docs/MIGRATION.md).
- **Production X-Wing encapsulation entropy now flows through the BCL CSPRNG
  directly.** The X25519 ephemeral private key was previously drawn from
  BouncyCastle's `SecureRandom`; it now comes from
  `System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)`, which
  goes straight to the OS entropy source. The semantics are unchanged — both
  are CSPRNGs — but the production randomness source is now the .NET BCL and
  no longer a BouncyCastle singleton. The `XWing.SecureRandom` static was
  retired (it had no other callers).

### Added

- **`PqJwtValidationParameters.RequireReplayProtection`** — when `true`, the
  `PqJwtValidator` constructor throws `ArgumentException` if no
  `ReplayCache` is supplied. Defaults to `false` so the historical opt-in
  default is preserved, but turning it on means an operator who forgets to
  wire a cache sees the misconfiguration at startup rather than as a silent
  missing defense at runtime. Two new tests in `PqJwtHooksTests` lock both
  branches.
- **`IXWingDeterministicCoins` internal test seam** — an
  `internal`-only-and-reachable-via-`InternalsVisibleTo` interface that lets
  the test suite inject deterministic ML-KEM outputs and a deterministic
  X25519 ephemeral private key into the encapsulation path. Production code
  *never* reaches this — the public `XWing.Encapsulate(recipient)` overload
  has no parameter for it. The seam exists to make the X-Wing combiner and
  the X25519 half KAT-able; the BCL `MLKem.Encapsulate` step still cannot
  be KAT'd and is now covered by an N=64 statistical sanity test
  (`XWingDeterministicTests.X_Wing_encapsulation_to_the_same_recipient_produces_distinct_outputs_across_64_iterations`)
  that asserts all 64 ciphertexts and all 64 shared secrets are distinct
  while every round-trip recovers the secret correctly.
- **Pinned end-to-end roundtrip corpus**
  (`tests/PostQuantum.Jwt.Tests/TestVectors/jwt-roundtrip-vectors.json`)
  with three entries: a signed token with `kid`/`jti`/`aud`/custom claim, a
  signed token with only `sub`+lifetime, and a signed-then-encrypted minimal
  token. Each vector pins the deterministic parts — the compact JSON of the
  protected header and payload — and asserts successful end-to-end
  validation. The non-deterministic parts (ML-DSA signature bytes, X-Wing
  KEM ciphertext, AES-GCM nonce / ciphertext / tag) are not pinned and the
  test file documents why.
- **README "Read this first — these tokens are intentionally
  non-interoperable" blockquote** at the very top of the README, above the
  preview/audit status block. Names the non-IANA `ML-DSA-65`, `X-Wing`,
  `A256GCM` identifiers and the standard JWT libraries that will reject
  these tokens (`System.IdentityModel.Tokens.Jwt`, `jose-jwt`, `node-jose`,
  `python-jose`, Auth0/Okta SDKs). Reinforces — does not replace — the
  existing mid-page comparison section. Operational caveats elsewhere in
  the README are unchanged.

### Fixed (correctness)

- **`PqJwtValidator.Validate` now wraps Base64/JSON/crypto-material parsing
  failures in `PqJwtValidationException`** instead of letting
  `FormatException`, `JsonException`, or `CryptographicException` leak to
  callers. Adversarial inputs that drove parsers deeper in the stack used
  to surface as those raw types — consumers that caught only
  `PqJwtException` saw a 500 instead of a 401. The fix is purely additive:
  the new outer exception carries the original as `InnerException` so
  diagnostics aren't lost. Found by SharpFuzz + in-process fuzz testing in
  the `PostQuantum.AspNetCore` repo. Two new tests in `PqJwtEdgeCaseTests`
  lock the new contract.

### Documentation

- **`KNOWN-GAPS.md`** — the "X-Wing encapsulation is not KAT-validated"
  bullet is narrowed to its actual remaining scope (BCL ML-KEM
  `Encapsulate` specifically); the combiner direction and the X25519
  ephemeral half are now exercised through the deterministic test seam and
  the 64-iteration statistical sanity test. The "Replay protection is
  opt-in" bullet now names `RequireReplayProtection` as the fail-closed
  opt-in.
- **`SECURITY.md`** supported-versions table updated to `1.0.0-preview.1`;
  older preview lines marked superseded.

## [0.3.0-preview.1] — 2026-05-30

A **real-world adoption** release. v0.2 made the existing surface trustworthy;
v0.3 makes it pleasant to wire into a real ASP.NET Core 10 app, makes it
AOT-friendly, and adds the supply-chain signals a production-grade crypto
package needs.

### Added

- **New companion package: `PostQuantum.Jwt.AspNetCore`.**
  - `AddPqJwtBearer(…)` extensions on `AuthenticationBuilder` — mirrors the
    shape of `AddJwtBearer` from `Microsoft.AspNetCore.Authentication.JwtBearer`,
    so post-quantum tokens slot into the standard auth pipeline.
  - `PqJwtBearerHandler` — fail-closed `AuthenticationHandler` that
    delegates to `PqJwtValidator`. Bypasses `Microsoft.IdentityModel`,
    which doesn't know `ML-DSA-65`.
  - `PqJwtBearerOptions` — strongly-typed configuration with sensible
    defaults (`NameClaimType="sub"`, `RoleClaimType="role"`).
  - `IPqJwtKeyRing` + `HttpPqJwtKeyRing` — JWKS-equivalent key directory
    fetched from a trusted HTTPS endpoint, cached in memory with
    configurable refresh, AOT-safe (source-gen JSON), exclusively
    accepting ML-DSA-65 entries.
- **AOT/trim-safe API path.** `WithClaim<T>(name, value, JsonTypeInfo<T>)`
  is a new source-gen-friendly overload alongside the existing
  reflection-based `WithClaim(name, object?)`. The reflection overload now
  carries `[RequiresUnreferencedCode]` and `[RequiresDynamicCode]` so AOT
  consumers see one targeted warning. Primitive setters (`WithIssuer`,
  `WithSubject`, `WithAudience`, `WithJwtId`, `WithExpiration`,
  `WithLifetime`, `WithNotBefore`) bypass reflection internally and stay
  trim-safe. Both projects declare `IsAotCompatible=true`.
- **CycloneDX SBOM packed inside the `.nupkg`.** Every `dotnet pack` runs
  the CycloneDX tool (if installed) and includes `bom.json` at the root
  of the package, alongside the existing top-level release-artifact SBOM.
- **Property-based tests** via FsCheck.Xunit: Base64Url involutive
  round-trip, URL-safety of encoded output, custom-claim round-trips,
  signature-tamper invariance, and X-Wing encapsulate/decapsulate
  matching. Total test count: **68** (was 57).
- **Linux PQ-required CI lane.** New `linux-pq-required` job installs
  OpenSSL 3.5+ via `conda-forge`, runs the suite with `LD_LIBRARY_PATH`
  pointed at it, and fails the run on any skipped test. Joins the
  Windows lane as cross-platform proof that the ML-KEM / ML-DSA / X-Wing
  paths actually executed in CI.
- **Release workflow author-signing hook.** Optional
  `NUGET_SIGNING_CERT` + `NUGET_SIGNING_CERT_PASSWORD` secrets on the
  `nuget-publish` environment trigger `dotnet nuget sign` with a
  DigiCert timestamp before push. Absent secrets log a notice and skip
  signing — the package still ships under nuget.org's repository
  signature.
- **`PackageValidationBaselineVersion` infrastructure.** Wired in
  conditionally (`-p:EnableBaselineValidation=true`) against
  `0.2.0-preview.3`; flip the switch once that baseline is published to
  nuget.org so future versions are checked for accidental API breaks.

### Changed

- The `pack` job in CI now packs both the main library and the AspNetCore
  companion.
- `pack-verify` CI installs the CycloneDX tool so the SBOM step runs on
  every PR.

### Documentation

- README "What's new in 0.3.0-preview.1" reorganised to lead with the
  preview.1 deltas, with the 0.2 trust line and 0.1 → 0.2 deltas
  following.
- README usage tour replaces the hand-rolled ASP.NET Core middleware with
  the `AddPqJwtBearer(…)` call from the new companion.

## [0.2.0-preview.3] — 2026-05-30

A **documentation release**. No code changes; same wire format, same crypto,
same 57/57 tests. This release exists so the package on nuget.org carries
the new adoption-focused docs.

### Added

- **ASP.NET Core 10 integration example** in `README.md`: DI registration of
  `PqJwtValidator` as a singleton, a minimal fail-closed bearer middleware,
  a protected minimal-API endpoint, and explicit notes on lifetime,
  replay-cache scope in a cluster, `kid`-based rotation, and why the
  standard `Microsoft.AspNetCore.Authentication.JwtBearer` handler can't
  validate `ML-DSA-65` (so this middleware deliberately bypasses it).

## [0.2.0-preview.2] — 2026-05-30

A defense-in-depth follow-up to `preview.1`, locking in items flagged by a
second independent review pass (the Gemini memo) on top of the first
(chatgpt memo). Still no new public capabilities.

### Changed (breaking — but only for misconfigured callers)

- **`PqJwtValidator(parameters, …)` now throws `ArgumentException` at
  construction time** if neither `SignatureVerificationKey` nor
  `SignatureKeyResolver` is configured. Previously this surfaced as
  `PqJwtException` on the first `Validate(…)` call. Callers that were
  already configuring a key are unaffected; callers that were constructing
  a "schema-only" validator without a key need to supply one (any valid
  ML-DSA-65 key works for structural-failure tests).
- **`XWingPublicKey.Import(…)` now parses the embedded ML-KEM-768
  encapsulation key at ingestion** and throws `PqJwtException` for a
  length-correct but structurally invalid key. Previously the parse was
  deferred to `XWing.Encapsulate(…)` and surfaced when the key was
  *used*. The thrown exception type is the same, just earlier.

### Added

- **CycloneDX SBOM in the release pipeline.** The release workflow now
  generates `bom.json` for the project's dependency graph (currently
  `BouncyCastle.Cryptography` plus the build-time `Microsoft.SourceLink.*`
  family), includes it in `SHA256SUMS.txt`, and issues a separate GitHub
  build-provenance attestation for it.
- **Test for the new fail-fast misconfiguration path** (`Validator_without_a_verification_key_or_resolver_throws_at_construction`).
  Total test count: **57**, zero skips on PQ-capable hosts.

### Internal

- Removed the now-redundant `ImportMlKemEncapsulationKey` wrapper in
  `XWing` — `XWingPublicKey.Import` is the single point of structural
  validation.
- Simplified `ResolveVerificationKey` to drop the runtime check that the
  constructor now enforces.

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

[Unreleased]: https://github.com/systemslibrarian/postquantum-jwt/compare/v1.0.0-preview.2...HEAD
[1.0.0-preview.2]: https://github.com/systemslibrarian/postquantum-jwt/compare/v1.0.0-preview.1...v1.0.0-preview.2
[1.0.0-preview.1]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v1.0.0-preview.1
[0.3.0-preview.1]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v0.3.0-preview.1
[0.2.0-preview.3]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v0.2.0-preview.3
[0.2.0-preview.2]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v0.2.0-preview.2
[0.2.0-preview.1]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v0.2.0-preview.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-jwt/releases/tag/v0.1.0-preview.1

---

*To God be the glory — 1 Corinthians 10:31.*
