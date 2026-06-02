# PostQuantum.Jwt

[![NuGet](https://img.shields.io/nuget/vpre/PostQuantum.Jwt?label=nuget&color=blue)](https://www.nuget.org/packages/PostQuantum.Jwt)
[![Downloads](https://img.shields.io/nuget/dt/PostQuantum.Jwt?color=blue)](https://www.nuget.org/packages/PostQuantum.Jwt)
[![CI](https://github.com/systemslibrarian/postquantum-jwt/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/systemslibrarian/postquantum-jwt/actions/workflows/ci.yml)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Post-quantum hybrid JWTs for .NET 10.** Signs with ML-DSA-65 (FIPS 204).
Optionally encrypts with X-Wing (X25519 + ML-KEM-768) and AES-256-GCM. Built
on the native .NET BCL post-quantum primitives. Fail-closed by design,
small-surface, and honest about what it is.

> ### Read this first — these tokens are intentionally non-interoperable
>
> PostQuantum.Jwt uses `alg = ML-DSA-65` and (optionally) `enc = X-Wing` /
> `cty = JWT` with `A256GCM`. **None of these identifiers are registered
> with IANA.** Tokens produced by this library will **not** validate in
> `System.IdentityModel.Tokens.Jwt`, `jose-jwt`, `node-jose`,
> `python-jose`, Auth0/Okta SDKs, or any other generic JWT tooling — and
> they will not until IANA registers post-quantum JOSE identifiers (a
> process this project does not control).
>
> This is the right library only when **you own both the issuer and every
> verifier** (closed system, internal service-to-service, your own
> mobile/desktop client, or a system you are bridging behind an
> interop-translating gateway). If you need a JWT that an arbitrary
> third-party stack can validate today, use
> `System.IdentityModel.Tokens.Jwt` with a NIST-approved classical
> algorithm instead — and revisit post-quantum once IANA-registered PQ
> identifiers and standards-track JOSE PQ profiles exist. See
> [Compared to System.IdentityModel.Tokens.Jwt](#compared-to-systemidentitymodeltokensjwt)
> for the side-by-side.

> **Status — `1.0.0-preview.2`. Preview software. Not for production use.**
> The API may change between previews, before the stable `1.0.0`. The
> cryptographic construction has **not** been
> independently audited. Read [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before depending
> on this for anything that matters.

---

## Table of contents

- [Why](#why)
- [What's new in 1.0.0-preview.2](#whats-new-in-100-preview2)
- [Install](#install)
- [60-second tour](#60-second-tour)
- [Usage](#usage)
  - [Sign and validate](#sign-and-validate)
  - [Sign *and* encrypt](#sign-and-encrypt)
  - [Key rotation and replay protection](#key-rotation-and-replay-protection)
  - [ASP.NET Core integration](#aspnet-core-integration)
- [Samples](#samples)
- [Token format](#token-format)
- [Public API at a glance](#public-api-at-a-glance)
- [Compared to System.IdentityModel.Tokens.Jwt](#compared-to-systemidentitymodeltokensjwt)
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
math behind today's JWT signatures (EdDSA, ECDSA, RSA). Pure post-quantum
schemes are new and comparatively under-attacked. **Hybrid** hedges both at
once:

- **Signatures — ML-DSA-65.** NIST-standardized lattice signature, FIPS 204,
  security category 3.
- **Key agreement — X-Wing.** The IETF hybrid KEM combining the battle-tested
  **X25519** with **ML-KEM-768** (FIPS 203), bound together by a SHA3-256
  combiner. An attacker must break *both* to recover the key.

If either half stands, your token stands. That is the whole point.

---

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
audited and the non-IANA identifiers mean tokens still do not interop with
generic JWT tooling. Changes are stacked newest-first.

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
- **"Read this first — these tokens are intentionally non-interoperable"
  disclosure** at the very top of the README, naming the non-IANA `ML-DSA-65`
  / `X-Wing` / `A256GCM` identifiers and the standard JWT libraries that
  will reject these tokens. Reinforces — does not replace — the existing
  mid-page `System.IdentityModel.Tokens.Jwt` comparison.
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
dotnet add package PostQuantum.Jwt --version 1.0.0-preview.2
```

Or in a `.csproj`:

```xml
<PackageReference Include="PostQuantum.Jwt" Version="1.0.0-preview.2" />
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
dotnet add package PostQuantum.Jwt.AspNetCore --version 1.0.0-preview.2
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

Nine runnable samples live in [`samples/`](samples/) — from a menu-driven console
tour to a real ASP.NET Core service, an interactive Blazor playground, refresh-token
rotation, and a distributed replay cache. Each references the library by project
reference, so the samples always build against the current source (CI builds the
whole sample solution on every push).

| Sample | Shows |
| --- | --- |
| [`ConsoleDemo`](samples/ConsoleDemo)                     | Every feature, fast — a Spectre.Console menu |
| [`WebApiDemo`](samples/WebApiDemo)                       | Real ASP.NET Core integration via `AddPqJwtBearer` |
| [`VerifierDemo`](samples/VerifierDemo)                   | Cross-service key rotation against an issuer's key directory |
| [`PqJwtPlayground`](samples/PqJwtPlayground)             | Interactive Blazor UI — build and validate tokens in a browser |
| [`RefreshTokenDemo`](samples/RefreshTokenDemo)           | Access/refresh split, rotation, reuse detection |
| [`DistributedReplayCache`](samples/DistributedReplayCache) | `IPqJwtReplayCache` over Redis / `IDistributedCache` |
| [`SpecByExample`](samples/SpecByExample)                 | xUnit tests whose names are the lessons |
| [`TestingSupport`](samples/TestingSupport)               | A no-crypto test auth handler for your own `[Authorize]` endpoints |

```bash
# build every sample
dotnet build samples/PostQuantum.Jwt.Samples.slnx
# or run one
dotnet run --project samples/ConsoleDemo
```

See [`samples/README.md`](samples/README.md) for the full guide,
[`samples/SECURE-USAGE.md`](samples/SECURE-USAGE.md) for the decisions *around* the
token, and [`samples/HARDENING-CHECKLIST.md`](samples/HARDENING-CHECKLIST.md) for
how each attack is blocked.

> **Live playground.** The Blazor playground can be hosted as an interactive demo —
> see [`samples/PqJwtPlayground/DEPLOY.md`](samples/PqJwtPlayground/DEPLOY.md).

---

## Token format

PostQuantum.Jwt uses JOSE-style compact serialization:

| Form      | Segments | Header `alg` / `enc`              |
|-----------|----------|-----------------------------------|
| Signed    | 3        | `ML-DSA-65`                       |
| Encrypted | 5        | `X-Wing` / `A256GCM` (nested JWT) |

These algorithm identifiers are **not** registered with IANA — see
[Security posture](#security-posture).

Full wire-format and combiner details are in [`docs/design.md`](docs/design.md).

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
problem: hybrid post-quantum JWTs. The trade-offs:

| Concern | `System.IdentityModel.Tokens.Jwt` | `PostQuantum.Jwt` |
|---|---|---|
| **Algorithms** | RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, HS256/384/512, etc. | **One suite only:** ML-DSA-65 for signatures, X-Wing + AES-256-GCM for encryption. |
| **Quantum resistance** | None of the standard algorithms are quantum-resistant. | Hybrid: classical *and* post-quantum, both must fall. |
| **Algorithm agility** | Yes (and historically the source of `alg: none`, RS/HS confusion, and downgrade attacks). | **No, by design.** The validator does not trust the token's `alg` to choose a path; it accepts exactly one. See [`docs/adr/0001-algorithm-agility.md`](docs/adr/0001-algorithm-agility.md). |
| **Standards interop** | Fully IANA-registered identifiers; tokens validate in every JWT library. | Identifiers (`ML-DSA-65`, `X-Wing`) are not IANA-registered. Tokens **will not** validate in generic JWT tooling. |
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

**Use `PostQuantum.Jwt` if** you specifically want hybrid post-quantum tokens
*now*, you control both the issuer and the verifier, and you accept that your
tokens won't validate in any other ecosystem until IANA registers these
identifiers and standard libraries catch up.

---

## Operational tradeoffs

Honest, decision-useful notes for the moment you're deciding whether to wire
this in.

**Token size.** A plain HS256 JWT is ~200 bytes. A signed PostQuantum.Jwt token
is **~4.5 KB**: ML-DSA-65 signatures are 3,309 bytes (vs. 32–64 for HMAC/EdDSA),
and that's after base64url encoding. A sign-then-encrypt token adds another
**~1.5 KB** (1,120-byte X-Wing ciphertext + 12-byte nonce + 16-byte AES-GCM
tag, base64url-encoded). Plan for ~5 KB signed, ~6.5 KB encrypted. This matters
if you put tokens in cookies, query strings, or constrained headers — for most
`Authorization: Bearer` flows it's fine, for cookies it likely is not.

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

**"Preview, not for production" — what that means operationally.** The leading
`1.0` signals the public API and wire format have stopped moving in
back-incompatible ways across preview revisions; the `preview.N` suffix
carries the maturity caveat (no independent audit, non-IANA identifiers).
A future `preview.N+1` may still adjust the surface if a security review
demands it. For an internal service you control end-to-end this is
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

- **Hybrid by construction.** Encryption stays secure unless *both* X25519 and
  ML-KEM-768 fall; signatures rest on ML-DSA-65.
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
- **Non-standard identifiers.** The `alg`/`enc` values describe a scheme the
  IANA JOSE registry does not cover, so these tokens are intentionally **not**
  interoperable with generic JWT tooling.
- **Preview.** Treat the API and wire format as unstable until the stable `1.0.0` release; the `1.0.0-preview.*` series may break between previews.

Full detail lives in [`SECURITY.md`](SECURITY.md) and
[`KNOWN-GAPS.md`](KNOWN-GAPS.md). To report a vulnerability, see `SECURITY.md`.

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

The full suite is **68 tests, zero skips** on a Windows 11 / .NET 10 host
with native ML-KEM and ML-DSA support. Both the Windows and Linux CI lanes
fail the run if any test skips.

---

## Contributing

Issues and pull requests are welcome. Before opening a PR:

1. Run `dotnet build` and `dotnet test` — both must be green, with **zero
   warnings** (the build treats compiler warnings as errors).
2. Keep the discipline in [`CLAUDE.md`](CLAUDE.md): honesty over polish,
   fail-closed always, no rolled-your-own crypto, native BCL first.
3. Security-sensitive changes should land alongside a test that locks in the
   fail-closed behavior.

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
