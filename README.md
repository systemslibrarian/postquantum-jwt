# PostQuantum.Jwt

[![NuGet](https://img.shields.io/nuget/vpre/PostQuantum.Jwt?label=nuget&color=blue)](https://www.nuget.org/packages/PostQuantum.Jwt)
[![Downloads](https://img.shields.io/nuget/dt/PostQuantum.Jwt?color=blue)](https://www.nuget.org/packages/PostQuantum.Jwt)
[![CI](https://github.com/systemslibrarian/postquantum-jwt/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/systemslibrarian/postquantum-jwt/actions/workflows/ci.yml)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Hybrid confidentiality, post-quantum signatures — JOSE-style tokens for
.NET 10.** PostQuantum.Jwt is a production-oriented preview library for
controlled .NET issuer/verifier systems that need JOSE-style post-quantum
tokens. It provides ML-DSA-65 signed tokens, optional hybrid X-Wing-style
confidentiality (X25519 + ML-KEM-768 with AES-256-GCM), strict algorithm
handling, fail-closed validation, replay-protection support, key-rotation
patterns, and hardened usage guidance. Built on the native .NET BCL
post-quantum primitives. It is **not independently audited** and is **not a
drop-in replacement for OAuth/OIDC/JWT middleware**.

> ### Read this first — these tokens target controlled systems, not generic JWT interop
>
> PostQuantum.Jwt signs with `alg = ML-DSA-65` and (optionally) encrypts with
> `enc = A256GCM` under `X-Wing` key management (`cty = JWT`). **ML-DSA-65 and
> A256GCM are registered JOSE identifiers, but this library's X-Wing
> key-management profile is not currently a standardized JOSE/JWE profile.**
> PostQuantum.Jwt is therefore intended for controlled issuer/verifier systems
> rather than generic JWT/JWE interoperability. Tokens produced by this library
> will **not** validate or decrypt in `System.IdentityModel.Tokens.Jwt`,
> `jose-jwt`, `node-jose`, `python-jose`, Auth0/Okta SDKs, or other generic JWT
> tooling — the X-Wing key-management profile has no standardized JOSE/JWE
> definition for them to follow.
>
> This is the right library only when **you own both the issuer and every
> verifier** (closed system, internal service-to-service, your own
> mobile/desktop client, or a system you are bridging behind an
> interop-translating gateway). If you need a JWT that an arbitrary
> third-party stack can validate today, use
> `System.IdentityModel.Tokens.Jwt` with a NIST-approved classical
> algorithm instead — and revisit broad interop once a standards-track
> JOSE/JWE profile for hybrid post-quantum key management exists. See
> [Compared to System.IdentityModel.Tokens.Jwt](#compared-to-systemidentitymodeltokensjwt)
> for the side-by-side.

> **Status — `1.0.0-preview.7`. Production-oriented preview for controlled
> systems; not independently audited.** The public API and wire format are held
> stable across the `1.0.0-preview.*` series — the `preview` suffix marks the
> **pending independent audit**, not API churn; no breaking changes are expected
> before the final `1.0.0` (a security review could still force one).
> "Production-oriented" describes the hardened
> defaults (strict validation, fail-closed, replay and key-rotation support) —
> **not** an audit sign-off: the cryptographic construction has **not** been
> independently reviewed. Use it only in systems where you control both issuer
> and verifier, and read [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before depending on
> this for anything that matters.

---

## Table of contents

- [Why](#why)
- [What's new in 1.0.0-preview.7](#whats-new-in-100-preview7)
- [What's new in 1.0.0-preview.6](#whats-new-in-100-preview6)
- [Install](#install)
- [60-second tour](#60-second-tour)
- [Usage](#usage)
  - [Sign and validate](#sign-and-validate)
  - [Sign *and* encrypt](#sign-and-encrypt)
  - [Key rotation and replay protection](#key-rotation-and-replay-protection)
  - [ASP.NET Core integration](#aspnet-core-integration)
- [Samples](#samples)
- [Editor tooling](#editor-tooling)
- [Token format](#token-format)
- [Public API at a glance](#public-api-at-a-glance)
- [Compared to System.IdentityModel.Tokens.Jwt](#compared-to-systemidentitymodeltokensjwt)
- [Standards and interoperability status](#standards-and-interoperability-status)
- [Operational tradeoffs](#operational-tradeoffs)
- [Observability](#observability)
- [Security posture](#security-posture)
- [Compatibility](#compatibility)
- [Building from source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

---

## Why

A cryptographically relevant quantum computer would break the elliptic-curve
math behind today's JWT signatures (EdDSA, ECDSA, RSA) and key agreement. This
library splits the response: **post-quantum signatures**, and **hybrid
confidentiality** for the optional encryption path.

- **Signatures — ML-DSA-65 (post-quantum, not hybrid).** NIST-standardized
  lattice signature, FIPS 204, security category 3. Signing is ML-DSA-65 only —
  there is no classical co-signature, so this is *not* a composite
  classical + PQ signature.
- **Key agreement — X-Wing (hybrid).** The IETF hybrid KEM combining the
  well-studied **X25519** with **ML-KEM-768** (FIPS 203), bound together by a
  SHA3-256 combiner. An attacker must break *both* to recover the key.

For the encrypted form, if either half of the key agreement stands, your token's
confidentiality stands. That hedge is the whole point of the hybrid KEM.

### What this package is — and is not

**It is** a production-oriented preview for *controlled* systems: ML-DSA-65
signed tokens, optional hybrid X-Wing-style confidentiality, strict algorithm
handling, fail-closed validation, replay-protection support, and key-rotation
patterns — with the security posture documented honestly.

**It is not** independently audited, and **not** a drop-in replacement for
OAuth/OIDC/JWT middleware or a generic JWT/JWE library.

| Intended use cases | Non-use cases |
|---|---|
| Controlled issuer/verifier services (same team owns both ends) | Public OAuth/OpenID Connect provider replacement |
| Internal/service-to-service APIs | Drop-in replacement for `Microsoft.AspNetCore.Authentication.JwtBearer` |
| Post-quantum migration experiments | Unaudited high-risk production deployments |
| Research prototypes & educational security engineering | Consumer-facing auth without careful, independent review |
| Systems behind an interop-translating gateway | Anywhere generic JWT/JWE interoperability is required |

---

## What's new in 1.0.0-preview.7

A focused **security** fix continuing the preview.6 fail-closed hardening pass.
No API change, no wire-format change; the public surface is identical.

- **Security: a JOSE header with duplicate JSON property names is now rejected
  as `PqJwtValidationException(MalformedJson)`.** `System.Text.Json`'s
  `JsonNode.Parse` defers building the underlying name→node dictionary until
  the first property access, so a header like
  `{"alg":"ML-DSA-65","typ":"JWT","typ":"JWT"}` slipped past the parser's
  `JsonException` catch and threw `ArgumentException` at the first indexer
  read — escaping `Validate` as an unsealed exception type. RFC 8259 §4
  declares duplicate JSON keys non-interoperable and RFC 7515 §4 requires
  unique JOSE header parameter names, so rejecting these is conformant.
  Pinned by a regression test (`Header_with_duplicate_keys_reports_MalformedJson`).
  Builder-minted tokens are unaffected.
- **Tier 2 coverage-guided fuzz target is now operational.** The
  `fuzz/PostQuantum.Jwt.Fuzz/` SharpFuzz + libFuzzer target was scaffolded in
  preview.6 but not yet run; in preview.7 it ran for hours and surfaced the
  duplicate-key bug above on its first session. A small scaffold fix
  (defer the instrumented validator construction into the `Fuzzer.LibFuzzer.Run`
  callback, narrow instrumentation to the parser path) ships with this release.
  The random-input `PqJwtFuzzTests` from preview.6 are unchanged.

## What's new in 1.0.0-preview.6

A **security and assurance** update. Two encrypted-path hardening fixes — both
surfaced by a new adversarial fuzz suite — plus a deeper, executable assurance
layer. The signed-token path is unchanged on the wire.

- **Security: AES-GCM tag length is pinned to the profile.** The validator no
  longer derives the authentication-tag length from the token; it requires the
  full 16-byte (128-bit) tag and a 12-byte nonce. Previously an attacker could
  truncate the tag (e.g. to 120 bits) and have it still authenticate against its
  prefix — an authentication-strength downgrade and token malleability. Tokens
  from this library's builder are unaffected.
- **Security: strict canonical base64url decoding** (RFC 7515 §2). Embedded
  whitespace and non-zero "slack" bits — which would let a *different* string
  decode to identical bytes and still verify/decrypt — are now rejected. Token
  strings are non-malleable.
- **Adversarial fuzzing + executable security invariants.** New `PqJwtFuzzTests`
  (fail-closed totality + no spurious acceptance) and `SecurityInvariantsTests`
  (signature-before-claims ordering, header-never-selects-algorithm, no profile
  downgrade) lock the orchestration guarantees. A **TLA+ model** of the validator
  (`docs/formal/`) is model-checked with TLC.
- **BenchmarkDotNet suite** (`benchmarks/`): throughput, serverless cold-start,
  and measured token sizes vs. a classical ES256 baseline.
- **Docs:** corrected encrypted-token size (~7.8 KB, was understated), a new
  `SECURITY.md` "Parser & protocol robustness" section, and a reconciled
  validation-ordering contract across `SPEC.md`, the audit prompt, and the docs.

## What's new in 1.0.0-preview.5

A **documentation and hardening** update — the library binary is **identical** to
`preview.3` (no code change; supersedes the unpublished `preview.4` tag):

- **Reworded the API-stability language.** The public API and wire format are
  held stable across the `1.0.0-preview.*` series; the `preview` suffix reflects
  the pending independent audit, not API churn. (Also: a free-for-OSS
  code-signing path via the SignPath Foundation is now noted in `KNOWN-GAPS.md`.)
- **Clarified JOSE/IANA standards status.** ML-DSA-65 (RFC 9964) and A256GCM
  (RFC 7518) are registered JOSE identifiers; the X-Wing key-management profile
  is not a standardized JOSE/JWE profile. New
  [Standards and interoperability status](#standards-and-interoperability-status)
  section and table.
- **Normative token profile** — [`docs/SPEC.md`](docs/SPEC.md) defines the v1
  profile (headers, claims, fail-closed validation order, rejection rules).
- **Expanded security model** ([`SECURITY.md`](SECURITY.md)) and a
  **production-readiness checklist** ([`samples/HARDENING-CHECKLIST.md`](samples/HARDENING-CHECKLIST.md)).
- **Precise hybrid language** throughout: hybrid confidentiality, ML-DSA-65
  (post-quantum, not hybrid) signatures.
- **Aligned positioning** across all packages: *production-oriented preview for
  controlled issuer/verifier systems; not independently audited; not a drop-in
  OAuth/OIDC/JWT replacement.*
- **Supply-chain:** added a CodeQL workflow, Dependabot, and `CONTRIBUTING.md`.

## What's new in 1.0.0-preview.3

A **docs and packaging** refresh — the library binary is **identical** to
`preview.2` (no code change). It exists so the package pages point where they should:

- **Live playground — https://pqjwt.systemslibrarian.dev** — build, validate, and
  *break* a post-quantum token in your browser, with a
  [how-to guide](https://github.com/systemslibrarian/postquantum-jwt/blob/main/samples/PqJwtPlayground/USING.md).
- **Sample links are now absolute URLs**, so they resolve on the NuGet package
  page, not only on GitHub.
- **Sample Dockerfiles fixed** to bring OpenSSL 3.5 (the Azure Linux base ships
  only 3.3.5 — too old for ML-DSA/ML-KEM, so the containers had started but
  failed closed on every token op).

## What's new in 1.0.0-preview.2

An **additive** release — the crypto core, public algorithm surface, and
fail-closed behavior are **unchanged** (no new suite, no algorithm agility). It
adds observability and a typed failure taxonomy, plus the runnable samples,
templates, and compile-time analyzers that grow the ecosystem.

- **Validation metrics.** The validator emits a `pqjwt.validations` counter on a
  `System.Diagnostics.Metrics` meter named `PostQuantum.Jwt`, tagged
  `outcome=success|failure` and — on failure — a coarse, bounded, **non-sensitive**
  `reason`. Opt in with OpenTelemetry or any meter listener; no new dependency,
  no token/claim/key material ever emitted. See [Observability](#observability).
- **Typed failure reasons.** A new public `PqJwtFailureReason` enum and
  `PqJwtValidationException.Reason` let callers (and the metric) categorize a
  rejection from a typed value instead of parsing the message. The fail-closed
  control flow is byte-for-byte unchanged.
- **Runnable samples** (`samples/`) and a **`dotnet new` template package**
  (`PostQuantum.Jwt.Templates` — `pqjwt-webapi`, `pqjwt-console`). See
  [Samples](#samples).
- **Expanded hardening guidance** — `samples/SECURE-USAGE.md` and
  `samples/HARDENING-CHECKLIST.md` now map common JWT attacks to the library's
  defenses and the metric `reason` that surfaces each.
- **Compile-time analyzers** — a new opt-in `PostQuantum.Jwt.Analyzers` package
  enforces the architecture in your IDE/build: **PQJWT001** forbids inspecting a
  token's header fields and **PQJWT002** flags per-call validator construction.
  Plus an AI semantic-audit prompt. See
  [`docs/SECURITY-AUDIT-TOOLS.md`](docs/SECURITY-AUDIT-TOOLS.md).

## What's new in 1.0.0-preview.1

A **maturity-tier bump** from `0.3.0-preview.1`. The crypto core and public
algorithm surface are unchanged — ML-DSA-65 + X-Wing + AES-256-GCM with
sign-then-encrypt and RFC 7516 AAD binding remain the only path, no algorithm
agility, no new suites. What 1.0 brings is a sharper safety posture, a tighter
exception contract, and the test seam needed to KAT the parts of X-Wing that
*can* be made deterministic. The `preview.N` suffix carries the maturity
caveat, not the leading `1.0`: the construction has **not** been independently
audited and the non-standardized X-Wing key-management profile means tokens
still do not interop with generic JWT tooling. Changes are stacked newest-first.

**New in v1.0.0-preview.1**

- **Opt-in fail-closed replay protection.**
  `PqJwtValidationParameters.RequireReplayProtection`, when `true`, makes the
  `PqJwtValidator` constructor throw if no `ReplayCache` is wired. Default is
  `false` (no behavior change for existing callers), but operators who turn it
  on catch a missing cache at startup rather than as a silent missing defense
  at runtime.
- **Parser-level failures now surface as `PqJwtValidationException`.**
  `Validate` wraps `FormatException` / `JsonException` /
  `CryptographicException` (raised by Base64Url decode, JSON header/payload
  parse, and crypto-material import) in `PqJwtValidationException` with the
  original kept as `InnerException`. Consumers that catch only
  `PqJwtException` no longer leak a 500 on adversarial input.
- **`IXWingDeterministicCoins` internal test seam** (visible via
  `InternalsVisibleTo` only — production code has no parameter for it). Lets
  the suite KAT the X-Wing combiner direction and the X25519 ephemeral half
  against the official IETF vectors. The BCL `MLKem.Encapsulate` step is
  still not KAT-able and is now covered by an N=64 statistical sanity test
  asserting all 64 ciphertexts *and* all 64 shared secrets are distinct while
  every round-trip recovers the secret correctly.
- **Production X25519 ephemeral entropy now flows through
  `RandomNumberGenerator`** instead of BouncyCastle's `SecureRandom`. Both
  are CSPRNGs and the wire output is bit-identical, but the production
  entropy source is now the .NET BCL and the ephemeral key is zeroed in a
  `finally` (the BC path did not).
- **Pinned end-to-end roundtrip corpus**
  (`tests/PostQuantum.Jwt.Tests/TestVectors/jwt-roundtrip-vectors.json`):
  signed-with-`kid`/`jti`/`aud`/custom-claim, signed-minimal, and
  signed-then-encrypted-minimal. Each vector pins the deterministic parts
  (compact JSON of protected header + payload) and asserts successful
  end-to-end validation; non-deterministic parts (ML-DSA signature, X-Wing
  ciphertext, AES-GCM nonce/ciphertext/tag) are not pinned and the file
  documents why.
- **"Read this first" interoperability disclosure** at the very top of the
  README, naming the `ML-DSA-65` / `X-Wing` / `A256GCM` identifiers, the
  non-standardized X-Wing key-management profile, and the standard JWT
  libraries that will reject these tokens. Reinforces — does not replace — the
  existing mid-page `System.IdentityModel.Tokens.Jwt` comparison.
- **`PostQuantum.Jwt.AspNetCore` is marked superseded by
  [`PostQuantum.AspNetCore`](https://github.com/systemslibrarian/postquantum-aspnetcore)**
  (cleaner naming, event-hook surface, hosted-service warmup, SignalR
  support, 40-test integration suite). Tokens minted by either validate in
  the other. The legacy companion receives critical fixes only — no new
  features — through 1.0.
- **Test count: 79/79 passing** on the full PQ lane (was 68 at v0.3).

**Previously, in v0.3.0-preview.1**

- **New companion package `PostQuantum.Jwt.AspNetCore`.**
  - `services.AddAuthentication().AddPqJwtBearer(...)` — mirrors the shape
    of `AddJwtBearer` from `Microsoft.AspNetCore.Authentication.JwtBearer`,
    so post-quantum tokens slot into the standard auth pipeline.
  - `PqJwtBearerHandler` — fail-closed `AuthenticationHandler` that
    delegates to `PqJwtValidator`. Bypasses `Microsoft.IdentityModel`, which
    doesn't know `ML-DSA-65`.
  - `IPqJwtKeyRing` + `HttpPqJwtKeyRing` — JWKS-equivalent: fetch a key
    directory from a trusted HTTPS endpoint with configurable refresh,
    in-memory cache, AOT-safe (source-gen JSON), single-suite enforcement.
- **AOT/trim-safe API path.** New `WithClaim<T>(name, value, JsonTypeInfo<T>)`
  overload alongside the existing reflection-based `WithClaim(name, object?)`.
  The reflection overload carries `[RequiresUnreferencedCode]` and
  `[RequiresDynamicCode]` so AOT publishers see one targeted warning;
  primitive setters (`WithIssuer`, `WithSubject`, etc.) bypass reflection
  internally and stay trim-safe. Both packages declare `IsAotCompatible=true`.
- **CycloneDX SBOM packed inside the `.nupkg`.** `bom.json` lives at the
  root of the package so consumers can inspect the dependency graph
  directly from nuget.org.
- **Property-based tests** via FsCheck.Xunit (Base64Url involutive
  round-trip, signature-tamper invariance, etc.). Total: **68 tests**,
  zero skips on PQ-capable hosts.
- **Linux PQ-required CI lane.** New `linux-pq-required` job installs
  OpenSSL 3.5+ via `conda-forge` and fails the run on any skipped test —
  joining the Windows lane in proving the ML-KEM / ML-DSA / X-Wing paths
  actually executed on every push, on both platforms.
- **Release workflow author-signing hook.** Optional
  `NUGET_SIGNING_CERT` + `NUGET_SIGNING_CERT_PASSWORD` secrets on the
  `nuget-publish` GitHub Environment trigger `dotnet nuget sign` with a
  DigiCert timestamp before push. Absent secrets log a notice and skip
  signing — the package still ships under nuget.org's repository signature.
- **API baseline infrastructure.** `PackageValidationBaselineVersion=0.2.0-preview.3`
  is wired in conditionally — pass `-p:EnableBaselineValidation=true`
  once the baseline is published to nuget.org and future versions are
  checked for accidental API breaks against it.

**New in v0.2.0-preview.3** (the previous release line, kept for reference)

- **Fail-fast misconfiguration.** `PqJwtValidator`'s constructor now throws
  `ArgumentException` if neither `SignatureVerificationKey` nor
  `SignatureKeyResolver` is configured — a security validator without a way
  to obtain a verification key is misconfigured by definition, and that
  should surface before the first token arrives, not after.
- **Eager X-Wing public-key validation.** `XWingPublicKey.Import` now parses
  the embedded ML-KEM-768 encapsulation key at ingestion. A length-correct
  but structurally invalid key fails with `PqJwtException` on import rather
  than later inside `XWing.Encapsulate`. Consumers handling untrusted key
  input see a single exception boundary.
- **SBOM (CycloneDX).** Every release now emits a `bom.json` covering the
  project's dependency graph, includes it in `SHA256SUMS.txt`, and issues a
  separate GitHub build-provenance attestation for it. The SBOM travels
  with the GitHub release artifacts rather than packed inside the `.nupkg`.

**The 0.1 → 0.2 delta, cumulative through `preview.2`**

- **Test coverage more than doubled** (27 → 57 tests, zero skips on PQ-capable
  hosts). New fail-closed locks for `nbf` in the future, clock-skew tolerance
  bounds, multi-audience tokens, `alg` confusion (`"none"` substitution),
  missing `alg`, malformed JSON header, array-shaped payload, wrong
  content-encryption (`A128GCM` instead of `A256GCM`), missing/wrong `cty` on
  encrypted tokens, tampered ciphertext, decryption with the wrong private
  key, replay protection across encrypted tokens, custom-claim round-trips,
  claim removal via `WithClaim(name, null)`, `XWingPrivateKey` dispose
  semantics, length-correct-but-malformed X-Wing public keys, negative
  `ClockSkew` configuration, validator-without-key configuration, and
  concurrent registration in `InMemoryReplayCache`.

- **Validator hardening.** Encrypted tokens now require `cty: JWT` on the
  outer header. The validator constructor refuses negative `ClockSkew`
  values *and* validators with no verification key. The decrypted plaintext
  buffer is zeroed alongside the shared secret. Malformed X-Wing public
  keys surface as `PqJwtException` rather than leaking `CryptographicException`
  from the BCL.

- **Release transparency.** `scripts/check-version-sync.sh` asserts the
  version is identical across `.csproj`, README, and CHANGELOG, and runs in
  CI on every push. The release workflow writes a `SHA256SUMS.txt` covering
  the `.nupkg`, `.snupkg`, and `bom.json`, and emits GitHub build-provenance
  attestations for both the `.nupkg` and the SBOM — any consumer can run
  `gh attestation verify <file> --repo systemslibrarian/postquantum-jwt` to
  confirm an artifact came from this repo's release workflow. Release steps
  and trust signals are documented in [`docs/RELEASE.md`](docs/RELEASE.md).

- **Windows CI is now the PQ-required lane.** It fails the run if any test
  reports skipped, so the ML-KEM / ML-DSA / X-Wing paths are *proven* to run
  in CI on every push, rather than relying on local verification alone.
  Linux remains the portability lane.
- **Documentation overhaul.** Rewritten README with a 60-second tour, a direct
  comparison vs. `System.IdentityModel.Tokens.Jwt`, and a clearer security
  posture. [`SECURITY.md`](SECURITY.md) and [`KNOWN-GAPS.md`](KNOWN-GAPS.md)
  refreshed to match the current state.
- **Build hygiene.** Build is **zero warnings** (was one CA1859 hint in 0.1).
  `EnablePackageValidation` is on. `LICENSE` and `CHANGELOG.md` are packed
  alongside the README so consumers see them in the package details on
  nuget.org.
- **CI hardening.** Workflows now run on actions versions that support
  Node.js 24, and the release pipeline is split into `pack` + `publish` with a
  GitHub Environment gate (`nuget-publish`) so publishing requires explicit
  manual approval.
- **Docs fix.** Corrected the X-Wing combiner formula in `SECURITY.md` — the
  label is concatenated **last**, matching the code and
  `draft-connolly-cfrg-xwing-kem`.

Full notes in [`CHANGELOG.md`](CHANGELOG.md).

---

## Install

```bash
dotnet add package PostQuantum.Jwt --version 1.0.0-preview.7
```

Or in a `.csproj`:

```xml
<PackageReference Include="PostQuantum.Jwt" Version="1.0.0-preview.7" />
```

**Runtime requirement:** the native ML-KEM / ML-DSA primitives need an OpenSSL
build that exposes them — **OpenSSL 3.5 or later** on Linux, or a recent
Windows. PostQuantum.Jwt fails closed with a clear error where they are
unavailable rather than silently falling back to weaker crypto.

---

## 60-second tour

```csharp
using System.Security.Cryptography;
using PostQuantum.Jwt;

using var signingKey      = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
using var verificationKey = MLDsa.ImportMLDsaPublicKey(
    MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());

string token = new PqJwtBuilder()
    .WithSubject("user-123")
    .WithLifetime(TimeSpan.FromMinutes(30))
    .SignWith(signingKey)
    .Build();

var result = new PqJwtValidator(new PqJwtValidationParameters
{
    SignatureVerificationKey = verificationKey,
}).Validate(token);

Console.WriteLine(result.Subject); // user-123
```

That's it: sign, validate. Anything wrong with the token — bad signature,
tampering, expiry, claim mismatch — throws `PqJwtValidationException`. There is
no "best-effort" result.

---

## Usage

### Sign and validate

```csharp
using System.Security.Cryptography;
using PostQuantum.Jwt;

using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

string token = new PqJwtBuilder()
    .WithIssuer("https://issuer.example")
    .WithSubject("user-123")
    .WithAudience("https://api.example")
    .WithLifetime(TimeSpan.FromMinutes(30))
    .WithClaim("role", "admin")
    .SignWith(signingKey)
    .Build();

using var verificationKey = MLDsa.ImportMLDsaPublicKey(
    MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());

var validator = new PqJwtValidator(new PqJwtValidationParameters
{
    SignatureVerificationKey = verificationKey,
    ValidIssuer   = "https://issuer.example",
    ValidAudience = "https://api.example",
});

PqJwtValidationResult result = validator.Validate(token);
Console.WriteLine(result.Subject);            // user-123
Console.WriteLine(result.GetString("role"));  // admin
```

### Sign *and* encrypt

When the payload is confidential, hand the builder a recipient's X-Wing public
key. The token is signed first, then encrypted ("sign-then-encrypt").

```csharp
using PostQuantum.Jwt.Cryptography;

// Recipient generates a key pair and publishes the public half.
using var recipient = XWingPrivateKey.Generate();
byte[] recipientPublic = recipient.PublicKey.Export();   // share this

string token = new PqJwtBuilder()
    .WithSubject("confidential-subject")
    .WithLifetime(TimeSpan.FromMinutes(5))
    .SignWith(signingKey)
    .EncryptFor(XWingPublicKey.Import(recipientPublic))
    .Build();

var validator = new PqJwtValidator(new PqJwtValidationParameters
{
    SignatureVerificationKey = verificationKey,
    DecryptionKey            = recipient,   // required for encrypted tokens
});

PqJwtValidationResult result = validator.Validate(token);
Console.WriteLine(result.WasEncrypted);  // True
```

### Key rotation and replay protection

Tag a signature with a `kid` and resolve it at validation time, and reject
replayed tokens with a `jti` cache:

```csharp
string token = new PqJwtBuilder()
    .WithKeyId("signing-key-2026")
    .WithJwtId(Guid.NewGuid().ToString("N"))
    .WithLifetime(TimeSpan.FromMinutes(5))
    .SignWith(signingKey)
    .Build();

var validator = new PqJwtValidator(new PqJwtValidationParameters
{
    // Pick a verification key from the token's kid (key rotation).
    SignatureKeyResolver = kid => keyRing.TryGetValue(kid, out var k) ? k : null,
    // Reject any jti seen before. InMemoryReplayCache is single-process;
    // implement IPqJwtReplayCache over a shared store for multi-node setups.
    ReplayCache = new InMemoryReplayCache(),
});
```

An unknown `kid`, a missing `jti`, or a replayed `jti` all fail closed.

> **Replay protection is OFF unless you wire a cache.** If
> `PqJwtValidationParameters.ReplayCache` is `null`, tokens carrying a
> `jti` are accepted but never registered — the same token may be replayed
> indefinitely. This is intentional for very-short-lived service-to-service
> tokens, but for any other deployment set
> `PqJwtValidationParameters.RequireReplayProtection = true` so the
> validator constructor throws at startup if a cache is missing. The flag
> fails closed; it does not silently downgrade behavior.

### ASP.NET Core integration

> **`PostQuantum.Jwt.AspNetCore` is superseded by
> [`PostQuantum.AspNetCore`](https://github.com/systemslibrarian/postquantum-aspnetcore).**
> Same engine (this library), cleaner naming, dedicated release cadence,
> richer event-hook surface (`OnMessageReceived` / `OnTokenValidated` /
> `OnAuthenticationFailed` / `OnChallenge`), hosted-service key-ring
> warmup, full SignalR support, and a 40-test integration suite. Tokens
> minted by either package validate in the other. New consumers should
> adopt `PostQuantum.AspNetCore` directly. The old companion will
> continue to receive critical fixes through 1.0 but no new features.
>
> **Migration guide:**
> [`postquantum-aspnetcore/docs/MIGRATION.md`](https://github.com/systemslibrarian/postquantum-aspnetcore/blob/main/docs/MIGRATION.md)
> — diff-style, mostly an `AddPqJwtBearer` → `AddPostQuantumJwtBearer`
> rename plus a scheme-name change.

The legacy companion's shape, for reference: install the companion
package and call `AddPqJwtBearer(...)` on the standard
`AuthenticationBuilder` — the same shape as `AddJwtBearer` from
`Microsoft.AspNetCore.Authentication.JwtBearer`, but routing through
`PqJwtValidator` instead of the IdentityModel handler that can't speak
`ML-DSA-65`.

```bash
dotnet add package PostQuantum.Jwt.AspNetCore --version 1.0.0-preview.7
```

```csharp
using System.Security.Cryptography;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(options =>
    {
        var keyBytes = Convert.FromBase64String(
            builder.Configuration["Auth:VerificationKey"]
                ?? throw new InvalidOperationException("Missing Auth:VerificationKey"));
        options.ValidationParameters = new PqJwtValidationParameters
        {
            SignatureVerificationKey = MLDsa.ImportMLDsaPublicKey(
                MLDsaAlgorithm.MLDsa65, keyBytes),
            ValidIssuer   = builder.Configuration["Auth:Issuer"],
            ValidAudience = builder.Configuration["Auth:Audience"],
            // Single-process replay defense. Swap to a Redis-backed
            // IPqJwtReplayCache for a horizontally scaled deployment.
            ReplayCache   = new InMemoryReplayCache(),
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/me", (HttpContext ctx) => new
{
    sub  = ctx.User.FindFirst("sub")?.Value,
    role = ctx.User.FindFirst("role")?.Value,
}).RequireAuthorization();

app.Run();
```

That's the whole integration. The handler is fail-closed by construction
(tampered / expired / wrong-issuer tokens produce
`AuthenticateResult.Fail`), `RequireAuthorization()` returns 401 to
unauthenticated callers, and standard `[Authorize(Roles = "...")]`
attributes work against the `"role"` claim by default.

**Key rotation across services.** Use `HttpPqJwtKeyRing` to fetch
verification keys from a trusted HTTPS endpoint (the post-quantum
analogue of JWKS):

```csharp
builder.Services.AddHttpClient<HttpPqJwtKeyRing>();
builder.Services.AddSingleton(sp =>
{
    var http = sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(HttpPqJwtKeyRing));
    return new HttpPqJwtKeyRing(http, new Uri(builder.Configuration["Auth:KeysEndpoint"]!));
});

builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(options =>
    {
        options.ValidationParameters = new PqJwtValidationParameters
        {
            // Resolved per token from the token's `kid` header.
            SignatureKeyResolver = kid =>
                builder.Services.BuildServiceProvider()
                    .GetRequiredService<HttpPqJwtKeyRing>()
                    .Resolve(kid),
            ValidIssuer   = builder.Configuration["Auth:Issuer"],
            ValidAudience = builder.Configuration["Auth:Audience"],
        };
    });
```

The expected key-directory document is JSON:
`{ "keys": [ { "kid": "...", "alg": "ML-DSA-65", "key": "<base64>" }, ... ] }`.
Entries with any other `alg` are ignored — the single-suite policy holds
across services.

**Don't `AddJwtBearer` alongside this.** The standard handler will try to
parse the token's `alg` and fail. Either use `AddPqJwtBearer` as your
only bearer auth, or restrict each scheme to specific routes with
`[Authorize(AuthenticationSchemes = ...)]`.

---

## Samples

Nine runnable samples live in
[`samples/`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples)
— a menu-driven console tour, a real ASP.NET Core service, an interactive Blazor
playground, refresh-token rotation, a distributed replay cache, and more. Each
references the library by project reference, so they always build against the
current source (CI builds the whole sample solution on every push).

> **▶ Live playground — https://pqjwt.systemslibrarian.dev** — build a token
> (claims, lifetime, optional X-Wing encryption), validate one, and see in plain
> language *why* a tampered or expired token is rejected — all in your browser, no
> install. (It's hosted scale-to-zero to keep costs near nothing, so the first
> request after it's been idle can take up to a minute to wake; reload if needed.)
> New to it? The
> [how-to guide](https://github.com/systemslibrarian/postquantum-jwt/blob/main/samples/PqJwtPlayground/USING.md)
> walks through building, validating, and *breaking* a token. Every *other* sample
> is source you clone and run locally — browse them all in
> [`samples/`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples).

| Sample | Shows |
| --- | --- |
| [`ConsoleDemo`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/ConsoleDemo) | Every feature, fast — a Spectre.Console menu |
| [`WebApiDemo`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/WebApiDemo) | Real ASP.NET Core integration via `AddPqJwtBearer` |
| [`VerifierDemo`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/VerifierDemo) | Cross-service key rotation against an issuer's key directory |
| [`PqJwtPlayground`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/PqJwtPlayground) | Interactive Blazor UI — the [live demo](https://pqjwt.systemslibrarian.dev) above |
| [`RefreshTokenDemo`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/RefreshTokenDemo) | Access/refresh split, rotation, reuse detection |
| [`DistributedReplayCache`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/DistributedReplayCache) | `IPqJwtReplayCache` over Redis / `IDistributedCache` |
| [`SpecByExample`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/SpecByExample) | xUnit tests whose names are the lessons |
| [`TestingSupport`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples/TestingSupport) | A no-crypto test auth handler for your own `[Authorize]` endpoints |

```bash
# clone, then build every sample
dotnet build samples/PostQuantum.Jwt.Samples.slnx
# or run one
dotnet run --project samples/ConsoleDemo
```

See [`samples/README.md`](https://github.com/systemslibrarian/postquantum-jwt/blob/main/samples/README.md) for the full guide,
[`samples/SECURE-USAGE.md`](https://github.com/systemslibrarian/postquantum-jwt/blob/main/samples/SECURE-USAGE.md) for the decisions *around* the
token, and [`samples/HARDENING-CHECKLIST.md`](https://github.com/systemslibrarian/postquantum-jwt/blob/main/samples/HARDENING-CHECKLIST.md) for
how each attack is blocked. To host your own playground, see
[`samples/PqJwtPlayground/DEPLOY.md`](https://github.com/systemslibrarian/postquantum-jwt/blob/main/samples/PqJwtPlayground/DEPLOY.md).

---

## Editor tooling

A companion **[VS Code extension](https://marketplace.visualstudio.com/items?itemName=systemslibrarian.postquantum-jwt)**
(`code --install-extension systemslibrarian.postquantum-jwt`) adds C# snippets, a structure-only
token decoder, and quick links for working with PostQuantum.Jwt. It does **no
cryptography** — it helps you write and read the code, and points at the
[live playground](https://pqjwt.systemslibrarian.dev) for anything that actually
signs or validates. Source lives in [`tools/vscode`](tools/vscode).

---

## Token format

PostQuantum.Jwt uses JOSE-style compact serialization:

| Form      | Segments | Header `alg` / `enc`              |
|-----------|----------|-----------------------------------|
| Signed    | 3        | `ML-DSA-65`                       |
| Encrypted | 5        | `X-Wing` / `A256GCM` (nested JWT) |

`ML-DSA-65` and `A256GCM` are registered JOSE identifiers; the `X-Wing`
key-management profile that ties them together here is not a standardized
JOSE/JWE profile, so these tokens are not interoperable with generic JWT
tooling — see [Standards and interoperability status](#standards-and-interoperability-status).

The normative token profile (headers, claims, validation order, rejection rules)
is in [`docs/SPEC.md`](docs/SPEC.md) — including a **token-format diagram** and a
**fail-closed validation-flow diagram** that mirrors the model-checked TLA+ spec;
full wire-format and combiner details are in [`docs/design.md`](docs/design.md). For measured token sizes, verification cost,
replay-protection posture, and an ASP.NET Core migration path, see
[**Post-quantum JWTs in .NET 10: cost and migration**](docs/PQ-JWT-COST-AND-MIGRATION.md).

---

## Public API at a glance

| Type                            | Purpose                                                                  |
|---------------------------------|--------------------------------------------------------------------------|
| `PqJwtBuilder`                  | Fluent builder for signed (3-part) or signed-then-encrypted (5-part) tokens. |
| `PqJwtValidator`                | Fail-closed validator. Thread-safe and reusable.                         |
| `PqJwtValidationParameters`     | Validation configuration: keys, issuer/audience, lifetime, replay cache. |
| `PqJwtValidationResult`         | The validated claims; only returned when every check passed.             |
| `PqJwtAlgorithms`               | Canonical `alg`/`enc` identifiers (e.g. `ML-DSA-65`, `X-Wing`, `A256GCM`). |
| `PqJwtException`                | Misconfiguration / usage error.                                          |
| `PqJwtValidationException`      | Token failed validation (subclass of `PqJwtException`).                  |
| `IPqJwtReplayCache`             | Optional `jti` replay-detection hook.                                    |
| `InMemoryReplayCache`           | Default single-process replay cache (use a distributed store in clusters). |
| `XWingPrivateKey` / `…PublicKey` | X-Wing hybrid KEM keys; `Generate()`, `Import()`, `Export()`.            |

---

## Compared to `System.IdentityModel.Tokens.Jwt`

`System.IdentityModel.Tokens.Jwt` (and the wider `Microsoft.IdentityModel.*`
family) is the right choice for the vast majority of JWT work today: it speaks
the IANA JOSE algorithms, interops with the entire OAuth / OpenID Connect
ecosystem, and has been hardened over a decade of production use. **Use it
unless you have a specific reason not to.**

PostQuantum.Jwt is a focused, deliberately *non-interoperable* tool for one
problem: JOSE-style post-quantum tokens (ML-DSA-65 signatures, optional hybrid
confidentiality) for controlled systems. The trade-offs:

| Concern | `System.IdentityModel.Tokens.Jwt` | `PostQuantum.Jwt` |
|---|---|---|
| **Algorithms** | RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, HS256/384/512, etc. | **One suite only:** ML-DSA-65 for signatures, X-Wing + AES-256-GCM for encryption. |
| **Quantum resistance** | None of the standard algorithms are quantum-resistant. | Post-quantum signatures (ML-DSA-65); hybrid confidentiality (X25519 *and* ML-KEM-768 must both fall). |
| **Algorithm agility** | Yes (and historically the source of `alg: none`, RS/HS confusion, and downgrade attacks). | **No, by design.** The validator does not trust the token's `alg` to choose a path; it accepts exactly one. See [`docs/adr/0001-algorithm-agility.md`](docs/adr/0001-algorithm-agility.md). |
| **Standards interop** | Fully IANA-registered identifiers; tokens validate in every JWT library. | `ML-DSA-65` and `A256GCM` are registered JOSE identifiers, but the `X-Wing` key-management profile that combines them here is **not** a standardized JOSE/JWE profile. Tokens **will not** validate in generic JWT tooling. |
| **`alg: none`** | Historically supported (and disastrous); now disabled by default. | **Impossible.** No unsigned path exists in the code. |
| **Default `exp` enforcement** | Configurable; default depends on the consumer (`TokenValidationParameters`). | Required by default. A token without an `exp` claim is rejected. |
| **Encryption** | JWE with many supported `alg`/`enc` combos. | Sign-then-encrypt only; `X-Wing` (X25519 + ML-KEM-768) → AES-256-GCM. One recipient per token. |
| **Replay defense** | Not built-in. | Built-in `IPqJwtReplayCache` + `InMemoryReplayCache`, opt-in via configuration. |
| **OAuth / OIDC integration** | First-class (`Microsoft.AspNetCore.Authentication.JwtBearer`, JWKS, etc.). | None. You wire the validator into your pipeline yourself. |
| **External audit** | Yes — widely deployed and reviewed. | **No.** Preview, not audited. |
| **Dependencies** | A family of `Microsoft.IdentityModel.*` packages. | Native .NET BCL + **one** package (`BouncyCastle.Cryptography`) for X25519 + SHA3-256. |
| **Target framework** | Multi-target (netstandard2.0 through net10). | `net10.0` only. |

**Use `System.IdentityModel.Tokens.Jwt` if** you need OAuth/OIDC interop, JWKS,
multi-algorithm agility, or any standards-conformant JWT.

**Use `PostQuantum.Jwt` if** you specifically want post-quantum signatures (and
optional hybrid confidentiality) *now*, you control both the issuer and the
verifier, and you accept that your tokens won't validate in another ecosystem
until a standards-track JOSE/JWE profile for hybrid post-quantum key management
exists and generic libraries adopt it.

---

## Standards and interoperability status

The primitives this library uses are mostly standardized; the *profile* that
ties them together is not. That distinction is the whole reason these tokens are
for controlled systems rather than generic interop.

| Component | Status |
|---|---|
| ML-DSA-65 signatures | Registered JOSE algorithm ([RFC 9964](https://www.rfc-editor.org/info/rfc9964/)); experimental use in this package |
| AES-256-GCM / A256GCM | Registered JOSE content-encryption algorithm ([RFC 7518](https://www.rfc-editor.org/info/rfc7518/)) |
| X-Wing / ML-KEM key management | Not currently a standardized JOSE/JWE profile |
| Generic JWT library interoperability | Not guaranteed |
| OAuth/OIDC production replacement | No |
| Controlled issuer/verifier systems | Intended use case |
| Independent cryptographic audit | Not yet completed |

**What this means in practice:**

- **Works best in closed systems** where the same team controls token issuing
  and token validation. Generic JWT/JWE libraries may not validate or decrypt
  these tokens, because the X-Wing key-management construction has no
  standardized profile for them to implement.
- **Header algorithm selection stays fail-closed.** The validator never trusts
  the token's `alg`/`enc` to choose a verification or decryption path — it
  accepts exactly one configured suite. See
  [`docs/adr/0001-algorithm-agility.md`](docs/adr/0001-algorithm-agility.md).
- **No unsafe algorithm fallback.** There is no `alg: none`, no unsigned path,
  and no silent downgrade; every validation or decryption failure throws.

---

## Operational tradeoffs

Honest, decision-useful notes for the moment you're deciding whether to wire
this in.

**Token size.** A classical ES256 JWT with the same claims is **315 bytes**
(measured). A signed PostQuantum.Jwt token is **~4.6 KB** — about **15×** larger;
the sign-then-encrypt form is **~7.8 KB**, about **25×**. ML-DSA-65 signatures
are 3,309 bytes (vs. ~64 for ES256), and that's after base64url encoding. The
encrypted token is bigger than "signed + the X-Wing ciphertext" alone because
the *entire* signed token becomes the AES-GCM plaintext and is then base64url-
encoded a second time (a ~33% inflation of the 4.6 KB inner token), on top of
the ~1.5 KB X-Wing KEM ciphertext (1,120 bytes) plus a 12-byte nonce and 16-byte
GCM tag. Plan for **~4.6 KB signed, ~7.8 KB encrypted**. This matters if you put
tokens in cookies, query strings, or constrained headers — for most
`Authorization: Bearer` flows it's fine, for cookies it likely is not. Reproduce
these numbers with
`dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --sizes`.

**Performance.** Sign/verify cost is dominated almost entirely by the native BCL
lattice operation (ML-DSA-65), and encryption by ML-KEM-768; the library's own
work — base64url, JSON, header assembly — is negligible beside a 3.3 KB
signature. Two practical consequences: per-token CPU is higher than HMAC/EdDSA
but fits comfortably in a `Bearer` validation path, and **first-call latency**
carries a one-time native-init + JIT cost that matters on serverless cold
starts. The [`benchmarks/PostQuantum.Jwt.Benchmarks`](benchmarks/PostQuantum.Jwt.Benchmarks)
project measures warm throughput, cold-start "time to first verified token", and
token size with BenchmarkDotNet — run it on your target hardware rather than
trusting a quoted figure.

**When to reach for encryption.** The `sign-then-encrypt` form is the right
choice only when the claims themselves are confidential (PII, account IDs you
don't want a leaked log holding). For the more common case — opaque session
references, role/scope strings — a signed-only token is correct: the signature
already prevents forgery, encryption just trades cost for secrecy you may not
need.

**Replay protection in a cluster.** `InMemoryReplayCache` works for a single
process and is fine for a development server or a single-instance worker. The
moment you scale horizontally, `jti`-based replay defense requires a shared
store — implement `IPqJwtReplayCache` over Redis, a database table, or
whichever cache the rest of your stack already uses. Until then a token
"replayed" on a different node is **not** detected.

**Key rotation.** `SignatureKeyResolver` selects a verification key from the
token's `kid` header. It does *not* fetch keys — there is no JWKS endpoint or
remote-discovery story. Your application is responsible for the key ring; this
library is just disciplined about asking for the right key when validating.

**"Production-oriented preview" — what that means operationally.** The leading
`1.0` signals the public API and wire format have stopped moving in
back-incompatible ways across preview revisions; the `preview.N` suffix
carries the maturity caveat (no independent audit, and a non-standardized
X-Wing key-management profile). A future `preview.N+1` may still adjust the
surface if a security review demands it. For an internal service you control
end-to-end this is
manageable. For a public API where third parties hold issued tokens, treat
the unaudited construction as the gating concern, not the wire format.

---

## Observability

`PqJwtValidator` emits a single counter so you can watch validation outcomes
without bolting on logging — and without ever logging anything sensitive.

- **Meter:** `PostQuantum.Jwt` (the name is stable API).
- **Counter:** `pqjwt.validations`, tagged `outcome` = `success` | `failure`, and
  on failure a `reason` drawn from the typed
  [`PqJwtFailureReason`](#public-api-at-a-glance) — a closed, bounded-cardinality
  set (e.g. `signature_mismatch`, `expired`, `replay_detected`,
  `algorithm_not_accepted`, `unknown_kid`, `audience_mismatch`). The `reason`
  **never** contains the token, claim values, `jti`, issuer/audience values, or
  key material — only the category.

It's emitted via `System.Diagnostics.Metrics`, so there's no telemetry
dependency in the package — opt in with OpenTelemetry or any meter listener:

```csharp
builder.Services.AddOpenTelemetry().WithMetrics(m => m
    .AddMeter("PostQuantum.Jwt")
    .AddPrometheusExporter());        // or OTLP, console, etc.
```

A spike in `pqjwt.validations{outcome="failure",reason="signature_mismatch"}` is
a live forgery signal. Because post-quantum signature verification costs more
than classical, this is also your DoS canary — see
[`samples/HARDENING-CHECKLIST.md`](samples/HARDENING-CHECKLIST.md). The same
typed `PqJwtFailureReason` is available on `PqJwtValidationException.Reason` for
callers that want to branch on the failure category directly.

## Security posture

We aim to be honest about exactly what this library does and does not give you.

**What you get**

- **Hybrid confidentiality, post-quantum signatures.** Encryption stays secure
  unless *both* X25519 and ML-KEM-768 fall; signatures are ML-DSA-65 only (not a
  hybrid classical + post-quantum signature).
- **Native post-quantum primitives.** ML-KEM-768 and ML-DSA-65 are the .NET
  BCL implementations, not a re-implementation.
- **Fail-closed validation.** Bad signature, tampered ciphertext, expired or
  not-yet-valid token, wrong issuer/audience, missing `exp`, missing `alg`, or
  an `alg` we don't expect — all throw. There is no `alg: none`, no unsigned
  path, and no silent downgrade.
- **Strict, small-surface defaults.** Expiration is required, clock skew is a
  modest 60 seconds, and only the exact post-quantum algorithms are accepted.

**What you must know**

- **One dependency — BouncyCastle — and why.** The .NET BCL does not ship
  X25519, the classical half of X-Wing. Rather than hand-roll elliptic-curve
  code, we use BouncyCastle's vetted X25519 (and its SHA3-256 for the X-Wing
  combiner). ML-KEM-768 and ML-DSA-65 remain on the native BCL. This trade-off
  is deliberate: we will not roll our own curve arithmetic.
- **Not audited.** No third party has reviewed this construction. X-Wing key
  generation and the decapsulation/combiner path **are** validated against the
  official IETF known-answer vectors; the encapsulation path is not (the native
  ML-KEM API is randomized). See [`KNOWN-GAPS.md`](KNOWN-GAPS.md).
- **Non-standardized profile.** `ML-DSA-65` and `A256GCM` are registered JOSE
  identifiers, but the `X-Wing` key-management profile that ties them together
  here is not a standardized JOSE/JWE profile. These tokens are therefore
  intentionally **not** interoperable with generic JWT tooling — see
  [Standards and interoperability status](#standards-and-interoperability-status).
- **Preview.** The public API and wire format are held stable across the `1.0.0-preview.*` series; the `preview` suffix reflects the pending independent audit, not expected API churn. No breaking changes are planned before the final `1.0.0`, though a security review could still force one.

Full detail lives in [`SECURITY.md`](SECURITY.md),
[`KNOWN-GAPS.md`](KNOWN-GAPS.md), the test pyramid in
[`docs/TESTING.md`](docs/TESTING.md), and — for verifying what you just
installed (build-provenance attestations, embedded SBOM, `SHA256SUMS`,
SourceLink, deterministic builds) — [`docs/SUPPLY-CHAIN.md`](docs/SUPPLY-CHAIN.md).
To report a vulnerability, see `SECURITY.md`.

---

## Compatibility

| Surface | Supported |
|---|---|
| Target framework | `net10.0` |
| Languages | C# 13 (any CLS-consuming language; the assembly is `[CLSCompliant(false)]` because the public surface exposes raw `byte[]` key material). |
| Operating system | Windows, Linux, macOS — anywhere .NET 10 + an OpenSSL build that exposes ML-KEM / ML-DSA runs. On Linux that's **OpenSSL 3.5 or later**. |
| AOT / trimming | Supported. Both `PostQuantum.Jwt` and `PostQuantum.Jwt.AspNetCore` declare `IsAotCompatible=true`. Use `WithClaim<T>(name, value, JsonTypeInfo<T>)` from a source-gen context for custom claims; the reflection-based `WithClaim(name, object?)` overload is annotated `[RequiresUnreferencedCode]` / `[RequiresDynamicCode]` so AOT publishers see one targeted warning. |

---

## Building from source

```bash
dotnet build
dotnet test
```

Tests that exercise the native post-quantum primitives **skip themselves** (with
a clear reason) on hosts that lack ML-KEM / ML-DSA support, and run fully where
OpenSSL 3.5+ is present.

If you're on a Linux box whose system OpenSSL predates 3.5, point the runtime
at a newer one:

```bash
LD_LIBRARY_PATH=/path/to/openssl-3.5/lib dotnet test
```

The full library suite is **119 tests, zero skips** on a host with native
ML-KEM and ML-DSA support (plus 11 analyzer tests). Both the Windows and Linux
CI lanes fail the run if any test skips.

---

## Contributing

Issues and pull requests are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md)
for the full guide. Before opening a PR:

1. Run `dotnet build` and `dotnet test` — both must be green, with **zero
   warnings** (the build treats compiler warnings as errors).
2. Keep the discipline in [`CLAUDE.md`](CLAUDE.md): honesty over polish,
   fail-closed always, no rolled-your-own crypto, native BCL first.
3. Security-sensitive changes should land alongside a test that locks in the
   fail-closed behavior.
4. Update [`docs/SPEC.md`](docs/SPEC.md) if you change the token profile.

**Cutting a release** is documented in [`docs/RELEASE.md`](docs/RELEASE.md).
It enumerates exactly what CI enforces, what humans review, and what
provenance signals each release carries — and is honest about what is still
missing (author code signing, SBOM).

**Reporting a vulnerability:** please **do not** open a public issue. Use
GitHub's *Report a vulnerability* button on the repository, or follow the
process in [`SECURITY.md`](SECURITY.md).

---

## License

[MIT](LICENSE).

---

*To God be the glory — 1 Corinthians 10:31.*
