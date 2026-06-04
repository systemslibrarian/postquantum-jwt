# PostQuantum.Jwt benchmarks

[BenchmarkDotNet](https://benchmarkdotnet.org/) measurements for the library. This
is a developer tool — it is **not** packed or shipped, and it is **not** part of
the `dotnet test` gate (benchmarks are long-running and need Release builds).

## What it measures

| Benchmark | What it tells you |
|---|---|
| `TokenBenchmarks` | Warm-path throughput + allocations for sign, verify, sign+encrypt, decrypt+verify. |
| `ClassicalBaselineBenchmarks` | The classical reference point: ES256 (ECDSA P-256) sign/verify via the modern `JsonWebTokenHandler`. |
| `ColdStartBenchmarks` | "Time to first verified token" in a **fresh process** — the number serverless hosts (Azure Functions, AWS Lambda) care about. |
| `--sizes` report | On-the-wire token size vs. the ES256 baseline — the headline cost of PQ JWTs (an ML-DSA-65 signature alone is ~3.3 KB). |

### Honest scope

- **The wall-clock is dominated by the native BCL lattice math** (ML-DSA
  sign/verify, ML-KEM encaps/decaps), which this library calls but does not
  implement. The surrounding glue (Base64url, JSON, header assembly) is a
  rounding error against a ~3.3 KB signature. These numbers exist to make that
  cost *visible and honest*, not to justify micro-tuning glue that doesn't move
  the total.
- **The classical baseline is ES256 via the modern `JsonWebTokenHandler`**
  (`Microsoft.IdentityModel.JsonWebTokens`), deliberately *not* the legacy
  `JwtSecurityTokenHandler` from `System.IdentityModel.Tokens.Jwt`. Racing this
  library against a deprecated, slower handler would flatter it; the fair fight
  is against the faster, currently-recommended path. ES256 (not HS256) because
  it is asymmetric like ML-DSA-65 — an apples-to-apples comparison.
- **No serializer comparison** (MessagePack/MemoryPack et al.). Those are binary
  serializers, not signing/PQC libraries; comparing a signed, PQ-secure token
  against an unsigned binary blob would measure nothing meaningful.

## Running

Requires native ML-DSA / ML-KEM — i.e. OpenSSL 3.5+. In this dev container the
system `libcrypto` predates ML-KEM, so prefix with conda's OpenSSL (same quirk
as the test suite; see the repo `CLAUDE.md`). The program refuses to run, with a
reason, if the primitives are unavailable — it never emits placeholder numbers.

```bash
# Everything
LD_LIBRARY_PATH=/opt/conda/lib dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --filter '*'

# Just the warm throughput benchmarks
LD_LIBRARY_PATH=/opt/conda/lib dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --filter '*TokenBenchmarks*'

# Just cold start
LD_LIBRARY_PATH=/opt/conda/lib dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --filter '*ColdStart*'

# PQ vs. classical ES256, side by side
LD_LIBRARY_PATH=/opt/conda/lib dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --filter '*TokenBenchmarks*' '*ClassicalBaseline*'

# Token-size report (fast; not a timing benchmark)
LD_LIBRARY_PATH=/opt/conda/lib dotnet run -c Release --project benchmarks/PostQuantum.Jwt.Benchmarks -- --sizes
```

`dotnet run` without `-c Release` will work but BenchmarkDotNet will (correctly)
warn that debug builds produce untrustworthy timings.

---

*To God be the glory — 1 Corinthians 10:31.*
