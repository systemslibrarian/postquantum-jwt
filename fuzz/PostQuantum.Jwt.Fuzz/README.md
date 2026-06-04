# Coverage-guided fuzzing (SharpFuzz + libFuzzer)

A coverage-guided fuzz target for `PqJwtValidator.Validate`. Unlike the in-suite
FsCheck fuzzing (`tests/.../PqJwtFuzzTests.cs`), which generates *random* inputs,
this uses **coverage feedback** to drive toward unexplored branches — the
higher-rigor complement that finds parser bugs random testing misses.

It checks the same two total properties: **fail-closed totality** (only
`PqJwtException` may escape `Validate`; any other exception is a crash/finding)
and **no spurious acceptance** (a fuzzer input can't forge an ML-DSA-65 signature,
so acceptance is a finding). See `Program.cs`.

> **Status:** scaffolded and verified to *compile*. The instrumented run below
> was **not** executed in the dev container (it needs clang + the SharpFuzz
> instrumenter and is a long-running job — intended for a workstation). Finish
> the one-time setup and run it there.

## Prerequisites (one-time)

- **PQ-capable OpenSSL (3.5+).** ML-DSA/ML-KEM come from the BCL via OpenSSL. On
  Linux, put a 3.5+ `libcrypto` on `LD_LIBRARY_PATH` (the repo's dev container
  uses `/opt/conda/lib`; see the root `CLAUDE.md`).
- **clang** (to build the `libfuzzer-dotnet` driver).
- **The SharpFuzz instrumenter:**
  ```bash
  dotnet tool install --global SharpFuzz.CommandLine
  ```
- **The `libfuzzer-dotnet` driver** — build once per machine following the
  SharpFuzz README (<https://github.com/Metalnem/sharpfuzz>):
  ```bash
  clang -fsanitize=fuzzer libfuzzer-dotnet.cc -o libfuzzer-dotnet
  ```

## Build, instrument, run

`fuzz/run.sh` wraps these steps; the gist:

```bash
# 1. Publish the target + the library next to it.
dotnet publish fuzz/PostQuantum.Jwt.Fuzz -c Release -o fuzz/bin

# 2. Instrument the library under test (adds coverage tracing).
sharpfuzz fuzz/bin/PostQuantum.Jwt.dll

# 3. Fuzz. Point LD_LIBRARY_PATH at PQ-capable OpenSSL.
LD_LIBRARY_PATH=/opt/conda/lib \
  ./libfuzzer-dotnet --target_path=fuzz/bin/PostQuantum.Jwt.Fuzz \
  fuzz/corpus -timeout=10 -rss_limit_mb=4096
```

libFuzzer prints coverage as it runs and writes any crash reproducer to
`crash-<hash>` — feed that file back to the target to reproduce. Let it run for
hours; the `fuzz/corpus` seeds give it a head start on the JWT shape.

## What a finding looks like

- A **crash file** = an input that made `Validate` throw something other than
  `PqJwtException` (a "weird machine"), **or** an input it *accepted* (the
  `InvalidOperationException` the target throws on success). Both are real bugs —
  add a deterministic regression test (see `SecurityInvariantsTests`) and fix.
- The two bugs the FsCheck suite already found (GCM tag truncation; non-canonical
  base64url) are fixed; this run is looking for what random testing didn't reach.
