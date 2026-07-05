# Known Gaps

A transparent, running list of what PostQuantum.Jwt does **not** yet do, what is
unverified, and where the sharp edges are. Honesty over polish: if something is
incomplete, it is listed here rather than glossed over. This file is part of the
contract with anyone evaluating the library.

Last reviewed for: `1.0.0`. Companion views — what *is* tested in
repo, by layer, with the commands to run each, lives in
[`docs/TESTING.md`](docs/TESTING.md); how to verify a release you just
installed (build-provenance, embedded SBOM, `SHA256SUMS`, SourceLink) lives in
[`docs/SUPPLY-CHAIN.md`](docs/SUPPLY-CHAIN.md); and the history of why the
`preview` suffix was dropped at `1.0.0` — and why the lack of an audit is now
a permanent documented limitation rather than a release gate — lives in
[`docs/ROADMAP-TO-1.0.md`](docs/ROADMAP-TO-1.0.md).

> **The single most important thing to know before adopting this library:**
> the cryptographic construction has **not** been independently audited, and
> **no audit is scheduled**. This is not a temporary preview caveat that will
> be resolved in a later release — as of `1.0.0` it is a **permanent, accepted
> limitation**. See "No external audit" immediately below.

## Cryptography

- **No external audit (permanent, documented limitation).** No third party has
  reviewed the design or implementation, and **none is scheduled.** This is the
  load-bearing caveat for the whole library. Through the preview series an
  independent audit was framed as *the* gate to `1.0`; at `1.0.0` that framing
  was dropped on purpose (see [`docs/ROADMAP-TO-1.0.md`](docs/ROADMAP-TO-1.0.md)):
  an unfunded project is unlikely to secure a formal cryptographic review, and
  staying in perpetual `preview` implied the gap by a version suffix instead of
  stating it plainly. What stands behind the construction instead is in-repo
  evidence, not a third-party sign-off: a fail-closed test suite (tampered
  signature/payload, `alg: none`, expiry/`nbf` skew, wrong key/issuer/audience,
  malformed input), property and coverage-guided fuzz testing, mutation testing
  (Stryker), a TLA+ model of the validator, KAT coverage of the key-generation
  and decapsulation/combiner paths, and the X-Wing draft co-authors' 2026-06-05
  confirmation that our randomized-ML-KEM handling is sound (see
  `docs/AUDIT-OUTREACH.md`). None of that is a substitute for an independent
  audit. **Adopt this only where you control both issuer and verifier and you
  accept the unaudited-construction risk with eyes open.** It is not appropriate
  for high-risk or public-facing deployments. If you can fund or perform an
  independent review, please reach out — outreach status is tracked in
  `docs/AUDIT-OUTREACH.md`.
- **ML-KEM encapsulation is not vector-KAT'd in the encaps direction (platform
  constraint — not an implementation oversight).** What *is* vector-checked:
  seed-based keygen reproduces every vector's public key; **every vector's
  `ct` is decapsulated against the corresponding `sk` and the recovered `ss`
  is asserted equal to the vector** (`XWingKatTests.Decapsulating_the_vector_
  ciphertext_yields_the_vector_shared_secret`) — this exercises `Decapsulate`
  and the SHA3-256 combiner against the same values as the encaps vectors,
  and it is the assurance pattern the X-Wing draft co-author **Bas Westerbaan
  confirmed (2026-06-05) is sufficient for a conforming implementation** on
  platforms that ship only a randomized ML-KEM (see `docs/AUDIT-OUTREACH.md`).
  The X-Wing **combiner direction** and the **X25519 ephemeral half** of
  encapsulation are additionally exercised deterministically through an
  internal test seam (`IXWingDeterministicCoins`, reachable only via
  `InternalsVisibleTo("PostQuantum.Jwt.Tests")` — production always uses the
  OS CSPRNG via `RandomNumberGenerator` and the BCL `MLKem`, never an
  injected coin source). The remaining un-vector-KAT'd path is the BCL
  `MLKem.Encapsulate` itself: it draws its own randomness and exposes no
  derandomized entry point, so the vectors' `eseed` cannot be injected. We
  cover it by a 64-iteration round-trip property test with a statistical
  sanity check (all 64 ciphertexts distinct, all 64 shared secrets distinct,
  every round-trip recovers the secret). A PR to formalise this pattern in
  X-Wing draft §5.4.1 is in flight; see `docs/AUDIT-OUTREACH.md` for status.
  If a derandomized BCL ML-KEM API becomes available, add the direct encaps
  KAT as well — but it would be additive, not corrective.
- **No independent ML-KEM / ML-DSA KATs in this repo.** We rely on the .NET BCL
  (FIPS-validated) for these primitives and do not re-test them here. If your
  threat model needs in-repo KATs, they are not present yet.
- **Ecosystem context — formal verification is happening, but not for our exact
  stack.** Major vendors are formally verifying ML-KEM and ML-DSA at the
  algorithm level (e.g. Apple's `corecrypto` lists Isabelle-verified ML-KEM/ML-DSA
  for 2026). That is directional confidence in the *standards* we build on — but
  it is verification of *those* implementations, not the OpenSSL/BCL code path
  this library actually calls, and it does not transfer to our glue. We note it
  as background, not as an assurance about PostQuantum.Jwt.
- **Constant-time behavior is inherited, not guaranteed.** We make no
  side-channel claims beyond what the BCL and BouncyCastle provide.
- **One algorithm suite only.** Only ML-DSA-65, ML-KEM-768, and AES-256-GCM are
  supported. There is no algorithm agility (e.g. ML-DSA-44/87, ML-KEM-512/1024)
  in this preview.
- **Signatures are pure post-quantum, not hybrid.** *Encryption* key-agreement is
  hybrid (X-Wing = X25519 + ML-KEM-768), so confidentiality survives a break of
  either primitive. *Signatures*, however, are pure ML-DSA-65 — not a composite
  like ECDSA+ML-DSA. ML-DSA is FIPS-204 standardized, and a single pure-PQ suite
  keeps the surface small and sidesteps the algorithm-confusion class entirely.
  The trade-off: there is no classical signature as a fallback against an
  undiscovered ML-DSA *implementation* flaw, which some transition guidance (e.g.
  BSI) prefers during the migration period. A hybrid signature suite is a
  candidate for a future version if that guidance hardens; it is a deliberate
  omission here, not an oversight.

## Tokens & protocol

- **Non-standardized JOSE/JWE profile.** `ML-DSA-65` (RFC 9964) and `A256GCM`
  (RFC 7518) are registered JOSE identifiers, but the `X-Wing` key-management
  profile that ties them together here is **not** a standardized JOSE/JWE
  profile, and there is no JWK/JWKS representation for ML-DSA keys in this
  library. Tokens will **not** validate or decrypt in generic JWT/JWE tooling
  without custom integration. The wire format is the stable v1 profile and is
  now under SemVer (`docs/SPEC.md`). This is **not** a public OAuth/OIDC
  replacement.
- **Replay protection is opt-in and only as strong as the cache you provide.**
  `IPqJwtReplayCache` + the bundled `InMemoryReplayCache` enforce single-use
  `jti` when configured, but the bundled `InMemoryReplayCache` is
  **development/single-process only**: it does not survive a restart and is not
  sufficient for multi-server production. Distributed deployments must back the
  hook with a shared store (see `samples/DistributedReplayCache`). With no cache
  configured, `jti` is carried but not enforced — set
  `PqJwtValidationParameters.RequireReplayProtection = true` to fail-closed at
  validator construction when that omission would be a security regression.
- **`kid` resolution is supported but does not fetch keys.**
  `SignatureKeyResolver` lets you select a verification key from the token's
  `kid` (key rotation); you still supply the keys — there is no JWKS endpoint or
  remote key discovery.
- **Single fixed algorithm suite (by design).** No algorithm agility — see
  [`docs/adr/0001-algorithm-agility.md`](docs/adr/0001-algorithm-agility.md).
- **Single recipient for encryption.** A token can be encrypted to exactly one
  X-Wing public key; multi-recipient JWE is not implemented.
- **No token compression (`zip:DEF`), no "Compact Mode".** A signed token is
  ~4.6 KB and an encrypted token is ~7.8 KB; ~95% of the signed token is the
  ML-DSA-65 signature itself, which is essentially indistinguishable from
  random by construction and **does not compress** (DEFLATE/Brotli/gzip on it
  is 0%, sometimes slightly negative). What's left to compress — the JOSE
  header (~40 B) and the claims payload (~100-300 B) — is a small fraction of
  the total. Compressing a 200-byte payload to ~100 B saves ~133 B after
  base64url, a ~3% reduction on a 4.6 KB token. The CPU side is asymmetric in
  the wrong direction: DEFLATE on KB-scale input is ~100-200 µs, and verify
  on this stack is ~86 µs on modern AVX2 (see
  [`docs/PQ-JWT-COST-AND-MIGRATION.md`](docs/PQ-JWT-COST-AND-MIGRATION.md)) —
  so adding decompression to the verify path roughly doubles its wall-clock
  for a few percent of token size, and `zip:DEF` JWEs have a documented
  decompression-bomb attack class. JWE's `"zip":"DEF"` (RFC 7516 §4.1.3)
  could be wired into the encrypted path specifically if a concrete header
  size limit forced it, but the savings are smaller still (the encrypted
  payload is mostly the inner signed token, which is mostly the incompressible
  signature). A CBOR-encoded "Compact Mode" header would save another ~20-30 B
  by replacing JSON, at the cost of breaking JOSE compact-serialization
  alignment — which is what makes the token recognisable to the playground
  decoder, the VS Code inspector, and the SPEC. Token size is the cost you
  design around (8 KB header limits are fine; cookies are not), not a cost
  the library can engineer away meaningfully. Revisitable if a real consumer
  reports a concrete >8 KB header limit problem.
- **No detached payloads, no JSON (non-compact) serialization.** Compact
  serialization only.

## API & lifecycle

- **Stable API under SemVer.** The public API and v1 wire format were held
  stable across the entire `1.0.0-preview.*` series and are now a `1.0.x`
  commitment: PATCH for fixes, MINOR for additive surface, MAJOR for any break.
  (The unaudited-construction limitation above is orthogonal to API stability —
  it is permanent and does not gate releases.)
- **No streaming / large-payload API.** Everything operates on in-memory
  `string` / `byte[]`.
- **The core `PostQuantum.Jwt` package has no DI / `IServiceCollection`
  integration** — you construct the builder/validator yourself. ASP.NET Core
  authentication *is* available via the companion package: `AddPqJwtBearer(...)`
  + the fail-closed `PqJwtBearerHandler` + `HttpPqJwtKeyRing` (a JWKS-equivalent
  for `kid`-based rotation) ship in `PostQuantum.Jwt.AspNetCore`, now superseded
  by [`PostQuantum.AspNetCore`](https://github.com/systemslibrarian/postquantum-aspnetcore).
  Adding DI to the core package itself remains a deliberate non-goal.
- **`PostQuantum.Jwt.AspNetCore` is frozen at 1.0.0 — no further version will
  ever be published** (decision of 2026-07-05). The nuget.org package is
  deprecated and unlisted; existing 1.0.0 consumers keep restoring, new
  consumers should use `PostQuantum.AspNetCore`. The freeze is enforced in the
  repo, not by memory: the project is `IsPackable=false`, the release and CI
  workflows no longer pack or push it, `scripts/check-version-sync.sh` pins
  template references to it at exactly 1.0.0, and `AddPqJwtBearer(...)` carries
  an `[Obsolete]` supersession notice (`PQJWT100`) for anyone building from
  source. The source stays in-tree and buildable so the 1.0.0 samples and
  fail-closed tests remain exercised. The `dotnet new pqjwt-webapi` template
  scaffolds against `PostQuantum.AspNetCore` (the sync script bans template
  references to the retired package and pins the successor's version — at
  its stable `1.0.0` since 2026-07-05, bumped manually with its releases).

## Tooling & environment

- **Native PQC requires OpenSSL 3.5+ (Linux) or a recent Windows.** Where
  ML-KEM / ML-DSA are unavailable, operations fail closed and the corresponding
  tests skip themselves with a stated reason.
- **PQ coverage in CI is proven on Windows *and* Linux** as of
  `1.0.0-preview.5`. The Windows lane runs natively; the Linux lane pins
  OpenSSL 3.5+ via `conda-forge` and points `LD_LIBRARY_PATH` at it before
  testing. Both lanes fail the run on any skipped test, so the
  ML-KEM / ML-DSA / X-Wing paths are proven to execute on every push on
  both platforms. **Disclosure:** for a window in mid-2026 (until
  2026-07-05) the Linux lane silently skipped its PQ tests while showing
  green — conda-forge began resolving `openssl>=3.5` to OpenSSL 4.x, whose
  `libcrypto.so.4` the .NET 10 runtime does not probe, and the zero-skip
  gate read only the *last* per-project summary line (the analyzers
  project, which has no PQ tests). Both bugs are fixed: the conda spec is
  pinned `<4` and the gate now sums skips across every summary line. The
  Windows lane was unaffected throughout.
- **Packages are not author-signed by default.** The release workflow has
  an optional author-signing hook: if a `NUGET_SIGNING_CERT` secret is
  present on the `nuget-publish` GitHub Environment, packages are signed
  with `dotnet nuget sign` and a DigiCert timestamp before push. Until a
  certificate is procured and that secret is populated, packages rely on
  nuget.org's repository signature alone. Every release also emits GitHub
  build-provenance attestations for the `.nupkg` and the SBOM — verify
  with `gh attestation verify <file> --repo systemslibrarian/postquantum-jwt`.
  *To close this (no code change required):* obtain a code-signing certificate,
  base64-encode the `.pfx`, and add it as `NUGET_SIGNING_CERT`
  (+ `NUGET_SIGNING_CERT_PASSWORD`) on the `nuget-publish` environment — the
  release workflow then author-signs automatically. Open-source projects can
  apply for a **free** certificate via the
  [SignPath Foundation](https://signpath.org/) rather than buying a commercial
  (DigiCert/Sectigo) cert. Until then, repository signing plus the
  build-provenance attestations above remain the trust signals.
- **Publishing auth migrated to NuGet Trusted Publishing (OIDC) — but the
  packages on nuget.org today were pushed manually.** As of `1.0.0` the
  release workflow's `publish` job uses NuGet Trusted Publishing: it mints a
  short-lived nuget.org key from the GitHub Actions OIDC token (`NuGet/login`)
  with no long-lived `NUGET_API_KEY` secret. **This applies to future releases
  only.** Every package published so far — the `1.0.0-preview.*` series *and*
  the `1.0.0` GA — was pushed manually with a personal API key because the old
  CI key was invalid, so those `.nupkg`s do **not** carry the CI
  build-provenance attestation (the per-release `CHANGELOG.md` transparency
  notes record this). The first release cut after the OIDC switch will be the
  first whose nuget.org artifact is CI-built and attestation-backed; this entry
  will be updated to reflect that once it has actually happened, not before.
- **CycloneDX SBOM is packed inside the `.nupkg`** (in addition to being
  uploaded as a release artifact and getting its own build-provenance
  attestation). Consumers can inspect `bom.json` directly from the
  package on nuget.org.

## Summary of limitations

A consolidated list, for quick scanning:

- **No independent cryptographic audit** has been completed, and none is
  scheduled — a permanent, documented limitation as of `1.0.0`.
- **Stable `1.0.x` package** — the API and v1 wire format are under SemVer and
  will not break within the major version.
- **Not a public OAuth/OIDC replacement** and **not guaranteed compatible with
  generic JWT/JWE libraries.**
- The **X-Wing key-management profile is not standardized** as a JOSE/JWE
  profile (the `ML-DSA-65` and `A256GCM` identifiers themselves are registered).
- **Signatures are ML-DSA-65 only**, not a hybrid classical + post-quantum
  signature.
- **Replay protection depends on the configured replay cache**; the bundled
  in-memory cache is development/single-process only and is not enough for
  multi-server production.
- **Key rotation is `kid`-based selection only** — you supply the keys; there is
  no JWKS endpoint, remote discovery, or HSM/KMS integration in the package.
- **.NET 10 + OpenSSL 3.5+** (or a recent Windows) is required, which limits
  portability.
- **Consuming applications must still** enforce authorization correctly and
  protect clients against XSS/CSRF and insecure token storage — the library
  authenticates tokens, it does not secure your application for you.
- **No formal verification.** Property/fuzz-style and known-answer tests exist
  (see `tests/`), but there is no machine-checked proof of correctness.

## Language we intentionally avoid

To keep the positioning honest, the docs and package metadata do **not** use
these terms about PostQuantum.Jwt:

- "production-grade crypto"
- "audited"
- "FIPS-validated module" (the underlying BCL primitives are FIPS-validated; the
  *library* is not a validated module)
- "OIDC replacement"
- "generic JWT compatible"
- "military-grade" / "battle-tested" / "unbreakable"
- "quantum-proof" in all contexts (signatures are post-quantum; confidentiality
  is hybrid — neither is an unconditional guarantee)

Preferred framing: **"production-quality library for controlled systems; not
independently audited (a permanent, documented limitation)."**

---

If you hit a gap not listed here, that itself is a gap — please open an issue so
it can be recorded honestly.

---

*To God be the glory — 1 Corinthians 10:31.*
