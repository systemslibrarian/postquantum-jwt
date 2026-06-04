# Post-quantum JWTs in .NET 10: cost and migration

**ML-DSA token size, verification cost, replay protection, and ASP.NET migration.**

A decision-useful guide for engineers evaluating PostQuantum.Jwt. It answers the
three questions that actually gate adoption — *how much bigger are the tokens, how
much slower is validation, and how do I wire it into an ASP.NET Core app* — with
**measured** numbers and honest caveats.

> This is an engineering guide, not a research paper. PostQuantum.Jwt is an
> integration over the .NET BCL's ML-DSA / ML-KEM primitives plus the X-Wing
> hybrid KEM (an IETF *draft*); there is no novel cryptography here. It is a
> **production-oriented preview for controlled issuer/verifier systems — not
> independently audited, and not a drop-in OAuth/OIDC/JWT replacement.** See
> [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).

## TL;DR

- **Token size is the headline cost**, not CPU: a signed PQ token is ~15× a
  classical ES256 JWT, an encrypted one ~25×. Fine for `Authorization: Bearer`
  headers; usually too big for cookies.
- **Verification — the hot path for an API — is cheap**, only ~3× an ES256
  verify (sub-millisecond). The expensive operation is *signing* (~34×), which
  issuers do far less often.
- **Replay protection is opt-in** and only as strong as the cache you wire in.
- **"Migration" means adding a PQ-protected path in a system you control**, not
  swapping your OIDC stack — these tokens are intentionally non-interoperable.

## How these numbers were produced

All figures come from the repo's BenchmarkDotNet suite
([`benchmarks/`](../benchmarks/PostQuantum.Jwt.Benchmarks)) and the `--sizes`
report, measured on **.NET 10**.

- **Sizes are exact and reproducible** — they don't depend on hardware.
- **Latencies are *indicative*, not authoritative.** They were taken with
  BenchmarkDotNet's `ShortRun` job inside a shared CI/dev container, so the
  confidence intervals are wide (signing in particular). Treat them as
  order-of-magnitude truth and **run the suite on your own hardware** before
  capacity-planning:

  ```bash
  # sizes (exact)
  dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --sizes
  # warm latency + allocations (use the default job for tighter numbers)
  dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --filter '*TokenBenchmarks*' '*ClassicalBaseline*'
  # serverless cold start
  dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --filter '*ColdStart*'
  ```

  The classical baseline is **ES256 (ECDSA P-256)** via the modern
  `JsonWebTokenHandler` — asymmetric like ML-DSA-65, so the comparison is
  apples-to-apples (not HS256), and the *faster* of Microsoft's two handlers so
  the comparison never flatters this library.

## 1. Token size

Exact, measured, same claim set (`iss`/`sub`/`aud`/`iat`/`exp`):

| Token | Size | vs. ES256 |
|---|---:|---:|
| Classical ES256 JWT (baseline) | 315 B | 1× |
| **Signed** (ML-DSA-65) | **4,624 B (~4.6 KB)** | **~15×** |
| **Signed + encrypted** (X-Wing + A256GCM) | **7,777 B (~7.8 KB)** | **~25×** |

The ML-DSA-65 signature alone is **3,309 bytes** (vs. ~64 for ES256) — that's the
bulk of the signed token. The encrypted form is larger than "signed + the X-Wing
ciphertext" because the *entire* signed token becomes the AES-GCM plaintext and
is base64url-encoded a second time (~33% inflation), on top of the ~1.5 KB X-Wing
KEM ciphertext, a 12-byte nonce, and a 16-byte tag.

**What it means in practice:** comfortable in an `Authorization: Bearer` header
(8 KB header limits are typical); **likely too large for cookies** and a poor fit
for query strings or other constrained channels. Size is the cost you must design
around.

## 2. Verification cost

Warm latency, *indicative* (ShortRun, shared container — see method note):

| Operation | ES256 | PQ (ML-DSA-65 / X-Wing) | Ratio |
|---|---:|---:|---:|
| Sign | ~36 µs | ~1.2 ms | ~34× |
| **Verify** | ~78 µs | **~0.24 ms** | **~3×** |
| Sign + encrypt | — | ~1.6 ms | — |
| Decrypt + verify | — | ~0.49 ms | — |

Allocations per op (indicative): PQ verify ~62 KB, sign ~42 KB, encrypt ~119 KB,
decrypt+verify ~178 KB; ES256 verify ~4 KB.

Two honest framings:

- **>95% of the time is the native BCL lattice operation**, which this library
  calls but does not implement. "Verification cost" is really "what ML-DSA-65
  verification costs"; the library's own glue (base64url, JSON, header assembly)
  is a rounding error against a 3.3 KB signature. You cannot tune it, and there's
  nothing to tune.
- **The asymmetry favours real auth workloads.** APIs *verify* far more than they
  *sign*, and verify is the cheap PQ operation (~0.24 ms, ~3× ES256). The
  expensive operation — signing at ~1.2 ms — is the issuer's, done once per login
  / token mint.

### Cold start (serverless)

For Azure Functions / AWS Lambda, time-to-first-request often matters more than
steady-state throughput. Measured **time to first verified token in a fresh
process** (generate key → sign → verify, including JIT and one-time native
ML-DSA initialisation): **~36 ms** (high variance). That one-time cost is paid
per cold process, not per request; steady-state verifies fall back to the ~0.24 ms
above.

## 3. Replay protection

Replay defense is **opt-in** and fail-closed by design:

- Provide an `IPqJwtReplayCache`; the bundled `InMemoryReplayCache` is
  **single-process / development only** (it does not survive a restart and is not
  shared across nodes).
- When a cache is configured, a token **must** carry a `jti` and **must** carry a
  usable `exp` (so the cache entry can expire) — both are enforced, and a repeat
  `jti` is rejected.
- With no cache configured, `jti` is carried but **not enforced** — the same token
  can be replayed. Set `RequireReplayProtection = true` to fail at validator
  construction when a cache is missing, so the omission surfaces at startup rather
  than as a silent gap at runtime.
- **Multi-node deployments must back the cache with a shared store** (Redis, a
  database table, etc.). See [`samples/DistributedReplayCache`](../samples/DistributedReplayCache).

If you don't need single-use semantics, short `exp` lifetimes plus issuer/audience
validation are the lighter-weight defense.

## 4. ASP.NET Core migration

**Set expectations first:** this is **not** a drop-in replacement for ASP.NET
Core's JWT bearer middleware or for OAuth/OIDC. The `ML-DSA-65` and `A256GCM`
identifiers are registered JOSE, but the **X-Wing key-management profile is not a
standardized JOSE/JWE profile**, so these tokens will **not** validate in generic
JWT/JWE tooling. "Migration" here means: *in a system where you control both the
issuer and the verifier, add (or switch to) a PQ-protected path.*

The companion package `PostQuantum.Jwt.AspNetCore` provides a fail-closed bearer
handler:

```csharp
builder.Services
    .AddAuthentication()
    .AddPqJwtBearer(options =>
    {
        // The verification key comes from your trusted key ring — NEVER the token.
        options.KeyRing = myPqJwtKeyRing;        // IPqJwtKeyRing (kid -> ML-DSA public key)
        options.ValidIssuer = "https://issuer.example";
        options.ValidAudience = "https://api.example";
        // options.ReplayCache = redisBackedCache; // for one-time-use tokens
    });
```

A pragmatic migration path for a controlled system:

1. **Coexist.** Register the PQ bearer scheme alongside your existing scheme;
   route new/internal clients to the PQ path while classical clients keep working.
2. **Rotate by `kid`.** Issue with a `kid`; the verifier resolves keys from a key
   ring (`SignatureKeyResolver` / `IPqJwtKeyRing`). There is no JWKS fetch — your
   app owns the key ring; retain old verification keys for the longest accepted
   token lifetime.
3. **Decide encryption per claim sensitivity.** Use signed-only for opaque
   session references and roles; reach for sign-then-encrypt only when the claims
   themselves are confidential (PII), accepting the ~7.8 KB size.
4. **Mind the size at the edge.** Confirm proxies/gateways allow ~8 KB headers;
   don't put these tokens in cookies.

See [`samples/WebApiDemo`](../samples/WebApiDemo) and the `dotnet new pqjwt-webapi`
template for a runnable starting point, and
[`samples/SECURE-USAGE.md`](../samples/SECURE-USAGE.md) /
[`samples/HARDENING-CHECKLIST.md`](../samples/HARDENING-CHECKLIST.md) for the
surrounding architecture.

## When this is (and isn't) the right tool

**Good fit:** an internal/controlled issuer→verifier system that wants
post-quantum signature security (and optional hybrid confidentiality) today,
where you own both ends and can absorb larger tokens.

**Wrong fit:** a public OAuth/OIDC provider, anywhere generic JWT interop is
required, anywhere tokens live in cookies or tight size budgets, or any setting
that needs an independently audited construction (this preview is not audited).

## Assurance posture

The properties this guide relies on are exercised, not just asserted:

- Reference **test vectors** for the X-Wing KEM (`spec/test-vectors.json`).
- **Adversarial fuzzing** (`PqJwtFuzzTests`) — which surfaced and drove fixes for
  two real encrypted-path issues (AES-GCM tag truncation; non-canonical base64url
  malleability).
- **Executable security invariants** (`SecurityInvariantsTests`) and a
  model-checked **TLA+** spec of the validator (`docs/formal/`).
- **Cross-platform CI** (Windows + Linux) that fails on any skipped PQ test.

See [`SECURITY.md`](../SECURITY.md) for the threat model and the "Parser &
protocol robustness" section, and [`docs/SPEC.md`](SPEC.md) for the normative v1
token profile.

---

*To God be the glory — 1 Corinthians 10:31.*
