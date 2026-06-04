# HANDOFF — point a fresh Claude session here

This note captures what was built in the 2026-06-04 session and exactly what to do
next. **Read `CLAUDE.md` first** (project guardrails), then this file.

## Project state (as of 2026-06-04)

- **Released `1.0.0-preview.6` to NuGet** — all four packages live and indexed:
  `PostQuantum.Jwt`, `PostQuantum.Jwt.AspNetCore`, `PostQuantum.Jwt.Analyzers`,
  `PostQuantum.Jwt.Templates`. Tag `v1.0.0-preview.6`, GitHub Release published.
- **All work is on `main`** (the maintainer does **not** use feature branches —
  commit and push directly to `main`).
- Tests: **132 passing, 0 skipped** locally with PQ-capable OpenSSL.

### Environment quirks (important)

- **Native ML-DSA/ML-KEM need OpenSSL 3.5+.** In the dev container, prefix test
  and benchmark runs with `LD_LIBRARY_PATH=/opt/conda/lib`. Without it, PQ tests
  skip (and `linux-pq-required` CI fails on any skip).
- **NuGet publish:** the CI `NUGET_API_KEY` (on the `nuget-publish` GitHub
  environment) is **invalid** — preview.5 and preview.6 were pushed **manually**
  with the key saved in `./nuget.key` (gitignored), so they lack the CI
  build-provenance attestation. The playground deploy secret (`AZURE_CREDENTIALS`)
  **is** healthy (site auto-deploys on push to `main`).

## What this session built (all on `main`, all committed)

A "production-quality + security" pass. In order:

1. **BenchmarkDotNet suite** (`benchmarks/`) — sign/verify/encrypt/decrypt
   throughput, serverless cold-start, `--sizes` report, with an ES256 baseline
   (modern `JsonWebTokenHandler`).
2. **Validation-ordering doc fix** — reconciled `PQ-JWT-AUDIT-PROMPT.md` §2 and
   the `CLAUDE.md` audit matrix with `SPEC.md`/code (`exp` is checked *after*
   signature verification, by design).
3. **Executable security invariants** (`tests/.../SecurityInvariantsTests.cs`) —
   ordering, header-never-selects-alg, no profile downgrade.
4. **Adversarial fuzzing** (`tests/.../PqJwtFuzzTests.cs`) — which **found two
   real security bugs**, both now fixed + regression-locked:
   - **AES-GCM tag truncation** (auth-strength downgrade) → validator now pins
     12-byte nonce / 16-byte tag (`PqJwtValidator.Decrypt`).
   - **Non-canonical base64url** (token malleability) → strict canonical decode
     (`Internal/Base64Url.cs`).
5. **TLA+ model** (`docs/formal/`) — model-checked with TLC (4,706 states, no
   error). Proves no-accept-without-verify, soundness, termination.
6. **Cost & migration guide** (`docs/PQ-JWT-COST-AND-MIGRATION.md`) — measured
   sizes (exact) + indicative latencies + replay + ASP.NET migration.
7. **Mermaid diagrams** — token-format (`docs/design.md`) and validation-flow
   (`docs/SPEC.md`).
8. **Fuzz Tier 1** — `FuzzProperty` (scales via `PQJWT_FUZZ_MAXTEST`), two new
   properties (time-claim shapes; encrypted-envelope with random KEM material),
   and a nightly **`.github/workflows/fuzz.yml`** deep-fuzz job (out of PR CI).
9. **Fuzz Tier 2 scaffold** — `fuzz/PostQuantum.Jwt.Fuzz/` SharpFuzz coverage-
   guided target. **Compiles; not yet run** (needs clang + sharpfuzz setup).

## TODO — what to do next (the laptop session)

Ordered by priority. Each is a tracked task (see the session task list too).

1. **Run Tier 2 coverage-guided fuzzing (the main multi-hour job).**
   - One-time setup: `dotnet tool install --global SharpFuzz.CommandLine`;
     install `clang`; build `libfuzzer-dotnet` (see
     `fuzz/PostQuantum.Jwt.Fuzz/README.md`).
   - Run: `LD_LIBRARY_PATH=/opt/conda/lib fuzz/run.sh` (point at PQ-capable
     OpenSSL; on a normal machine use any OpenSSL 3.5+).
   - Let it run for hours. **Triage any `crash-*` file:** reproduce, add a
     deterministic regression test (mirror `SecurityInvariantsTests`), fix the
     validator, re-run. Document fixes in `CHANGELOG.md` under `[Unreleased]`.
2. **Trigger the nightly deep-fuzz once to confirm it's green:**
   `gh workflow run "Deep fuzz" -f maxtest=50000` and watch it.
3. **Fix the CI release pipeline** so future releases publish *with* provenance:
   set a valid `NUGET_API_KEY` on the `nuget-publish` environment (the working
   key is in `./nuget.key`). Then reject/dismiss the parked release run
   (`gh run list --workflow release.yml`).
4. **Eyeball the Mermaid diagrams** render correctly on GitHub
   (`docs/SPEC.md`, `docs/design.md`); fix syntax if any don't.
5. **(Optional) Re-run benchmarks on real hardware** and replace the *indicative*
   latency numbers in `docs/PQ-JWT-COST-AND-MIGRATION.md` with authoritative
   figures (commands are in that doc's "How these numbers were produced").
6. **If Tier 2 finds + fixes anything, cut `1.0.0-preview.7`** — bump version in
   all 4 csproj + README snippets + template content (`scripts/check-version-sync.sh`
   enforces sync), finalize the `[Unreleased]` changelog section, tag
   `v1.0.0-preview.7`, and publish (ideally via the now-fixed CI key).

## Quick commands

```bash
# full test suite (PQ-capable)
LD_LIBRARY_PATH=/opt/conda/lib dotnet test
# deep fuzz locally
PQJWT_FUZZ_MAXTEST=50000 LD_LIBRARY_PATH=/opt/conda/lib \
  dotnet test tests/PostQuantum.Jwt.Tests --filter "FullyQualifiedName~PqJwtFuzzTests"
# version-sync check before any release
bash scripts/check-version-sync.sh
# model-check the validator (needs Java + tla2tools.jar)
cd docs/formal && java -cp /path/to/tla2tools.jar tlc2.TLC PqJwtValidator.tla
```

## Guardrails reminder (from CLAUDE.md)

Honesty over polish; fail-closed always; don't roll your own crypto (BCL first,
BouncyCastle only for X25519/SHA3); keep the surface small; every doc footer ends
with the faith line. Don't reintroduce interop/“production-ready”/“audited”
overclaims — this is an unaudited **production-oriented preview**.

---

*To God be the glory — 1 Corinthians 10:31.*
