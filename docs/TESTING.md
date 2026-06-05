# Testing & assurance

A reviewer-facing summary of what PostQuantum.Jwt is actually tested for, with
links to the files that do the testing and the commands to run them yourself.
This document exists because the strongest test pyramid in the world is only
worth what an outside reviewer can *see* — so this page is the index.

Honest framing up front: this is a **production-oriented preview** that has
**not** had an independent cryptographic audit. The test pyramid below is the
internal assurance story; it is not a substitute for one. See
[`KNOWN-GAPS.md`](../KNOWN-GAPS.md) for what is deliberately not tested in
repo and why.

## The pyramid

| Layer | Where | What it covers |
|---|---|---|
| **Unit / round-trip** | [`tests/PostQuantum.Jwt.Tests/PqJwtRoundtripTests.cs`](../tests/PostQuantum.Jwt.Tests/PqJwtRoundtripTests.cs) | Build → validate happy paths, encrypted round-trip, `kid`-based key rotation, lifetime and clock skew. |
| **Strict encoding** | [`Base64UrlTests.cs`](../tests/PostQuantum.Jwt.Tests/Base64UrlTests.cs) | Canonical base64url decode (RFC 7515 §2). Rejects embedded whitespace and non-zero "slack" bits so two distinct strings cannot decode to the same bytes — preview.6 hardening. |
| **End-to-end token KATs** | [`PqJwtRoundtripVectorTests.cs`](../tests/PostQuantum.Jwt.Tests/PqJwtRoundtripVectorTests.cs) + [`TestVectors/jwt-roundtrip-vectors.json`](../tests/PostQuantum.Jwt.Tests/TestVectors/jwt-roundtrip-vectors.json) | Pinned end-to-end vectors for the signed and encrypted token shapes. |
| **X-Wing KATs** | [`XWingKatTests.cs`](../tests/PostQuantum.Jwt.Tests/XWingKatTests.cs) + [`TestVectors/xwing-vectors.json`](../tests/PostQuantum.Jwt.Tests/TestVectors/xwing-vectors.json) | The three official `draft-connolly-cfrg-xwing-kem` test vectors — decapsulation + the SHA3-256 combiner path, end-to-end. |
| **X-Wing determinism seam** | [`XWingDeterministicTests.cs`](../tests/PostQuantum.Jwt.Tests/XWingDeterministicTests.cs) | Exercises the combiner direction and the X25519 ephemeral half through an internal seam (production always uses the OS CSPRNG). |
| **Failure-reason taxonomy** | [`PqJwtFailureReasonTests.cs`](../tests/PostQuantum.Jwt.Tests/PqJwtFailureReasonTests.cs) | Every `throw new PqJwtValidationException(...)` site is pinned to its `PqJwtFailureReason` enum value, so the typed `reason` metric tag stays sound and the bounded cardinality holds. |
| **Security invariants** | [`SecurityInvariantsTests.cs`](../tests/PostQuantum.Jwt.Tests/SecurityInvariantsTests.cs) | Executable validator-orchestration contract: unknown `kid` rejected *before* ML-DSA verify (cheap-check-first DoS guard); signature verified *before* any claim is trusted; a 5-part encrypted token whose inner plaintext isn't a 3-part signed JWT rejected as `InnerNotSigned` (no profile downgrade). |
| **Property-based** | [`PqJwtPropertyTests.cs`](../tests/PostQuantum.Jwt.Tests/PqJwtPropertyTests.cs) | FsCheck-quantified properties over generated inputs. |
| **Tier 1 fuzz (random)** | [`PqJwtFuzzTests.cs`](../tests/PostQuantum.Jwt.Tests/PqJwtFuzzTests.cs) | FsCheck adversarial: random strings, structurally-shaped base64url garbage, and structure-aware mutations of valid tokens. Two total properties — **fail-closed totality** (only `PqJwtException` may escape `Validate`) and **no spurious acceptance** (a fuzzer can't forge an ML-DSA-65 signature, so acceptance is a finding). Scales via the `PQJWT_FUZZ_MAXTEST` env var. |
| **Tier 2 fuzz (coverage-guided)** | [`fuzz/PostQuantum.Jwt.Fuzz/`](../fuzz/PostQuantum.Jwt.Fuzz/) (SharpFuzz + libFuzzer) | Same two total properties as Tier 1, but driven by coverage feedback. **In its first operational run it found a real bug** (duplicate-key JOSE header escaping `Validate` as `ArgumentException`); fix shipped in `1.0.0-preview.7`. ~21M+ iterations across two follow-up runs with 0 net findings. |
| **TLA+ formal model** | [`docs/formal/PqJwtValidator.tla`](formal/PqJwtValidator.tla) | Model-checked with TLC (~4,706 distinct states explored). Proves no-accept-without-verify, soundness, and termination at the spec level. |
| **Metrics emission** | [`PqJwtMetricsTests.cs`](../tests/PostQuantum.Jwt.Tests/PqJwtMetricsTests.cs) | The `pqjwt.validations` counter is emitted on every outcome, the `reason` tag has bounded cardinality (the `PqJwtFailureReason` enum), and no token / claim / key material leaks into telemetry. |
| **ASP.NET Core integration** | [`PqJwtAspNetCoreTests.cs`](../tests/PostQuantum.Jwt.Tests/PqJwtAspNetCoreTests.cs) | The bearer handler, the `HttpPqJwtKeyRing` JWKS-equivalent, and integration with the standard auth pipeline. |
| **Roslyn analyzer tests** | [`tests/PostQuantum.Jwt.Analyzers.Tests/`](../tests/PostQuantum.Jwt.Analyzers.Tests/) | `HeaderIgnoranceAnalyzer` (PQJWT001) — flags consumer code that inspects token header fields; `ValidatorReuseAnalyzer` (PQJWT002) — flags per-call validator construction. Both are *semantic* (Roslyn semantic model), not text-pattern. |
| **Boundary tests (Stryker-driven)** | [`BoundaryTests.cs`](../tests/PostQuantum.Jwt.Tests/BoundaryTests.cs) | Off-by-one and overflow boundary conditions specifically identified by Stryker.NET as surviving mutants on `PqJwtValidator`: `MaxTokenLength`, `exp`/`nbf` skew edges, and `UnixSecondsMin`/`Max` parser bounds. Writing the `exp == UnixSecondsMax` test surfaced a real fail-closed totality bug (raw `ArgumentOutOfRangeException` escape from `exp + skew` overflow); the fix and the regression-locking test ship together. |
| **Mutation testing** | [`stryker-config.json`](../stryker-config.json) (Stryker.NET 4.x) | Scoped to the parser + validator path. Latest run: **66.31% raw mutation score** over 183 testable mutants. After filtering the ~40 surviving String-mutator results on exception-message text (which the failure-reason taxonomy intentionally doesn't assert on — tests pin the `PqJwtFailureReason` enum, not the message string), **~87% on behaviorally-meaningful mutations**. Run locally with `dotnet stryker`; HTML report in `StrykerOutput/`. The first operational run found the `exp+skew` overflow bug listed in the row above. |
| **Benchmarks (not tests)** | [`benchmarks/PostQuantum.Jwt.Benchmarks/`](../benchmarks/PostQuantum.Jwt.Benchmarks/) | BenchmarkDotNet: sign / verify / sign+encrypt / decrypt+verify, cold-start "time-to-first-verified-token", and an exact token-size report. Not part of `dotnet test`; perf regression reference. |

## Current numbers

As of `1.0.0-preview.7` (+ in-flight boundary tests):

- **155 tests passing, 0 skipped** — 144 in `PostQuantum.Jwt.Tests` (133 from
  preview.7 + 11 Stryker-driven boundary tests) + 11 in
  `PostQuantum.Jwt.Analyzers.Tests`.
- **Mutation kill rate** (Stryker.NET on parser + validator path): 66.31% raw,
  ~87% on behaviorally-meaningful mutations after filtering the exception-
  message-string survivors. The first Stryker run surfaced a fail-closed
  totality bug (`exp + skew` overflow at `DateTimeOffset.MaxValue`) which was
  shipped fixed in the same commit as the boundary tests.
- **Tier 2 fuzz:** 1 finding (fixed and regression-locked in preview.7);
  ~21M+ subsequent iterations across two runs with 0 net findings, coverage
  flat at ~10 cov / ~396 features.
- **TLA+ model:** ~4,706 distinct states explored, no error trace.
- **Latency reference (Windows 11 / .NET 10.0.8 / x64 RyuJIT AVX2, BenchmarkDotNet `DefaultJob`):**
  ML-DSA-65 verify **86 µs** (faster than ES256 verify at 115 µs on the same
  host), ML-DSA-65 sign 550 µs, sign + encrypt 773 µs, decrypt + verify 214 µs,
  cold start 21 ms. Full table in [`docs/PQ-JWT-COST-AND-MIGRATION.md`](PQ-JWT-COST-AND-MIGRATION.md).

## What is deliberately *not* tested in repo

These are not oversights — they are documented choices. See
[`KNOWN-GAPS.md`](../KNOWN-GAPS.md) for the long form.

- **No raw ML-DSA / ML-KEM KATs.** The .NET BCL primitives are FIPS-CAVP
  validated by NIST; re-testing them in this repo is redundant assurance
  rather than real assurance. What *is* KAT-validated here is the
  library-specific glue: the X-Wing combiner (three official vectors) and the
  end-to-end token shapes.
- **No third-party security audit.** This is a preview; the `preview` suffix
  marks the *pending* independent audit, not API churn.
- **No constant-time guarantees beyond what the BCL and BouncyCastle provide.**
- **One algorithm suite only** — `ML-DSA-65` + `X-Wing` + `A256GCM`. No
  agility, no composite signatures, no in-token compression. See
  [`docs/adr/0001-algorithm-agility.md`](adr/0001-algorithm-agility.md).

## Running it yourself

```bash
# 1. The full 144-test suite. ~5 seconds locally on a modern AVX2 box.
dotnet test
```

If `dotnet test` reports skipped tests on Linux, your `libcrypto` predates
ML-KEM. The library needs OpenSSL 3.5+ for native ML-DSA / ML-KEM; on Windows
.NET 10 ships its own. In the repo's dev container use:

```bash
LD_LIBRARY_PATH=/opt/conda/lib dotnet test
```

### Tier 1 deep fuzz

```bash
# Default ~5,000 cases per property; scale up for nightly-style runs:
PQJWT_FUZZ_MAXTEST=50000 dotnet test tests/PostQuantum.Jwt.Tests \
  --filter "FullyQualifiedName~PqJwtFuzzTests"
```

The nightly **Deep fuzz** GitHub Actions workflow
([`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml)) runs this at
`maxtest=50000` out of PR CI; trigger ad-hoc with
`gh workflow run "Deep fuzz" -f maxtest=50000`.

### Tier 2 coverage-guided fuzz

Prerequisites (one-time): `clang`,
`dotnet tool install --global SharpFuzz.CommandLine`, and the
`libfuzzer-dotnet` driver built once with
`clang -fsanitize=fuzzer libfuzzer-dotnet.cc -o libfuzzer-dotnet`. Then:

```bash
fuzz/run.sh
```

Let it run for hours. Any `crash-*` file in the working directory is a
finding — feed it back to the target to reproduce, add a deterministic
regression test mirroring `SecurityInvariantsTests`, fix the validator, and
re-run. See [`fuzz/PostQuantum.Jwt.Fuzz/README.md`](../fuzz/PostQuantum.Jwt.Fuzz/README.md)
for the full setup including the rationale for which assemblies are
SharpFuzz-instrumented (the parser / validator path, not the cryptography
path — the latter must run uninstrumented at process startup because
SharpFuzz coverage hooks are only valid inside `Fuzzer.LibFuzzer.Run`).

### TLA+ model checking

```bash
cd docs/formal
java -cp /path/to/tla2tools.jar tlc2.TLC PqJwtValidator.tla
```

The configuration is in [`PqJwtValidator.cfg`](formal/PqJwtValidator.cfg).
See [`docs/formal/README.md`](formal/README.md) for what is and isn't
proved.

### Benchmarks

```bash
# Sizes (exact, hardware-independent):
dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --sizes

# Warm latency + allocations (DefaultJob; takes ~5-10 minutes):
dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- \
  --filter '*TokenBenchmarks*' '*ClassicalBaseline*'

# Cold start (20 fresh-process launches):
dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- \
  --filter '*ColdStart*'
```

## CI orchestration

- [`ci.yml`](../.github/workflows/ci.yml) runs the 144-test suite on every push
  and pull request, on Windows *and* Linux (PQ coverage is proven on both).
- [`fuzz.yml`](../.github/workflows/fuzz.yml) is the nightly Tier 1 deep-fuzz
  job, out of PR CI so it doesn't slow contributions.
- [`codeql.yml`](../.github/workflows/codeql.yml) is GitHub's static security
  analysis.
- [`release.yml`](../.github/workflows/release.yml) packs, attests build
  provenance with [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance),
  and publishes the four NuGet packages on tag push.

## When you find something

If you spot a real bug, please open an issue with a reproducer. If it has a
security impact, follow [`SECURITY.md`](../SECURITY.md) instead.

---

*To God be the glory — 1 Corinthians 10:31.*
