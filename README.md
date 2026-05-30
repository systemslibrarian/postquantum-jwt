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

> **Status — `0.2.0-preview.3`. Preview software. Not for production use.**
> The API may change before 1.0. The cryptographic construction has **not** been
> independently audited. Read [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before depending
> on this for anything that matters.

---

## Table of contents

- [Why](#why)
- [What's new in 0.2.0-preview.3](#whats-new-in-020-preview1)
- [Install](#install)
- [60-second tour](#60-second-tour)
- [Usage](#usage)
  - [Sign and validate](#sign-and-validate)
  - [Sign *and* encrypt](#sign-and-encrypt)
  - [Key rotation and replay protection](#key-rotation-and-replay-protection)
  - [ASP.NET Core integration](#aspnet-core-integration)
- [Token format](#token-format)
- [Public API at a glance](#public-api-at-a-glance)
- [Compared to System.IdentityModel.Tokens.Jwt](#compared-to-systemidentitymodeltokensjwt)
- [Operational tradeoffs](#operational-tradeoffs)
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

## What's new in 0.2.0-preview.3

A **quality and trust** release line. No new public APIs in 0.2.x — every
change makes the existing surface safer or easier to reason about, or makes
adoption smoother. The changes below are stacked newest-first; the broader
0.1 → 0.2 delta is at the bottom.

**New in preview.3** (real-world adoption docs)

- **ASP.NET Core 10 integration example.** A copy-paste-ready section in
  [Usage → ASP.NET Core integration](#aspnet-core-integration): DI
  registration of `PqJwtValidator` as a singleton, a minimal fail-closed
  bearer middleware that bypasses the standard `JwtBearer` handler (which
  doesn't know `ML-DSA-65`), a protected minimal-API endpoint, plus notes on
  lifetime, replay-cache scope in a cluster, and `kid`-based rotation.
- No code changes from `preview.2`. Same `57/57` tests, same wire format,
  same crypto.

**New in preview.2** (second independent review pass)

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
dotnet add package PostQuantum.Jwt --version 0.2.0-preview.3
```

Or in a `.csproj`:

```xml
<PackageReference Include="PostQuantum.Jwt" Version="0.2.0-preview.3" />
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

### ASP.NET Core integration

The standard `Microsoft.AspNetCore.Authentication.JwtBearer` handler delegates
to `Microsoft.IdentityModel.Tokens.JsonWebTokenHandler`, which only knows the
IANA-registered `alg` values — it has no path for `ML-DSA-65`. Until that
changes, the cleanest integration in ASP.NET Core 10 is a small piece of
middleware that calls `PqJwtValidator` directly. Register the validator as a
singleton (it's immutable and thread-safe) and hand the resulting claims to
the rest of the pipeline as a `ClaimsPrincipal`.

```csharp
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.Jwt;

var builder = WebApplication.CreateBuilder(args);

// 1) Register PqJwtValidator once for the lifetime of the app.
builder.Services.AddSingleton<PqJwtValidator>(_ =>
{
    var keyBytes = Convert.FromBase64String(
        builder.Configuration["Auth:VerificationKey"]
            ?? throw new InvalidOperationException("Missing Auth:VerificationKey"));
    var verificationKey = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, keyBytes);

    return new PqJwtValidator(new PqJwtValidationParameters
    {
        SignatureVerificationKey = verificationKey,
        ValidIssuer   = builder.Configuration["Auth:Issuer"],
        ValidAudience = builder.Configuration["Auth:Audience"],
        // Single-process replay defense. Swap to a Redis-backed
        // IPqJwtReplayCache for a horizontally scaled deployment.
        ReplayCache   = new InMemoryReplayCache(),
    });
});

var app = builder.Build();

// 2) Bearer middleware — minimal, fail-closed. A missing or invalid token
//    leaves ctx.User unauthenticated; an explicitly malformed Bearer header
//    returns 401 directly. This deliberately bypasses the standard JwtBearer
//    handler because IdentityModel can't validate ML-DSA-65 signatures.
app.Use(async (ctx, next) =>
{
    var auth = ctx.Request.Headers.Authorization.ToString();
    const string prefix = "Bearer ";
    if (!auth.StartsWith(prefix, StringComparison.Ordinal))
    {
        await next();
        return;
    }

    var token = auth[prefix.Length..];
    var validator = ctx.RequestServices.GetRequiredService<PqJwtValidator>();

    try
    {
        var result = validator.Validate(token);
        var claims = result.Claims
            .Where(kv => kv.Value.ValueKind == JsonValueKind.String)
            .Select(kv => new Claim(kv.Key, kv.Value.GetString()!))
            .ToList();
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType: "PqJwt"));
    }
    catch (PqJwtValidationException)
    {
        // Fail closed: tampered/expired/wrong-issuer tokens → 401, no fallback.
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return;
    }

    await next();
});

// 3) A protected endpoint. Any handler can read ctx.User.FindFirstValue("sub"),
//    role, custom claims, etc. — they all came out of PqJwtValidator's
//    fail-closed pipeline.
app.MapGet("/me", (HttpContext ctx) =>
{
    if (!(ctx.User.Identity?.IsAuthenticated ?? false))
    {
        return Results.Unauthorized();
    }
    return Results.Ok(new
    {
        sub  = ctx.User.FindFirstValue("sub"),
        role = ctx.User.FindFirstValue("role"),
    });
});

app.Run();
```

A few notes on the integration:

- **Singleton lifetime.** `PqJwtValidator` is documented as thread-safe and
  immutable; one instance for the app is correct.
- **Replay cache scope.** `InMemoryReplayCache` is per-process. In a multi-node
  deployment, implement `IPqJwtReplayCache` over Redis (or whatever your
  cluster shares) so a token replayed on a different node is still rejected.
- **`kid`-based rotation.** Swap `SignatureVerificationKey` for
  `SignatureKeyResolver = kid => keyRing.TryGetValue(kid, ...)` once you
  start rotating keys; the rest of the middleware stays identical.
- **Don't mix with `AddAuthentication()`/`AddJwtBearer()`.** The standard
  handler will try to parse the token's `alg` and fail. Either use this
  middleware as your only auth path, or use it after explicitly disabling
  the standard handler for the routes you want post-quantum-protected.

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

**"Preview, not for production" — what that means operationally.** The wire
format and public API are not stable yet. If you ship 0.2.0-preview.3 in a
service and a future release bumps to 0.3.0 with a wire-format change, you
will be re-signing every active token (and possibly running a flag-day
migration). For an internal service you control end-to-end this is
manageable. For a public API where third parties hold issued tokens, treat
this as a blocker until 1.0.

---

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
- **Preview.** Treat the API and wire format as unstable until 1.0.

Full detail lives in [`SECURITY.md`](SECURITY.md) and
[`KNOWN-GAPS.md`](KNOWN-GAPS.md). To report a vulnerability, see `SECURITY.md`.

---

## Compatibility

| Surface | Supported |
|---|---|
| Target framework | `net10.0` |
| Languages | C# 13 (any CLS-consuming language; the assembly is `[CLSCompliant(false)]` because the public surface exposes raw `byte[]` key material). |
| Operating system | Windows, Linux, macOS — anywhere .NET 10 + an OpenSSL build that exposes ML-KEM / ML-DSA runs. On Linux that's **OpenSSL 3.5 or later**. |
| AOT / trimming | Not yet validated. The library uses `System.Text.Json` reflection paths; expect to need source-generated contexts before publishing AOT. |

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

The full suite is **57 tests, zero skips** on a Windows 11 / .NET 10 host with
native ML-KEM and ML-DSA support — and the Windows CI lane fails the run if
any test skips.

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
