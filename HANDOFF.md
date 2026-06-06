# HANDOFF — point a fresh Claude session here

This note captures the current state of the project for someone (or some
agent) picking it up cold. **Read `CLAUDE.md` first** (project guardrails),
then this file.

## Project state (as of 2026-06-05)

- **Latest release: `1.0.0-preview.8` on nuget.org** — all four packages
  live and indexed: `PostQuantum.Jwt`, `PostQuantum.Jwt.AspNetCore`,
  `PostQuantum.Jwt.Analyzers`, `PostQuantum.Jwt.Templates`. Tag
  `v1.0.0-preview.8`, GitHub Release published.
- **All work is on `main`** (the maintainer does **not** use feature
  branches — commit and push directly to `main`).
- **176 tests passing in the default suite, 0 skipped**: 165 in
  `PostQuantum.Jwt.Tests` + 11 in `PostQuantum.Jwt.Analyzers.Tests`.
  One opt-in timing-distribution test runs via
  `dotnet test --filter Category=Timing`.
- **Live demo:** <https://demo.pqjwt.systemslibrarian.dev> —
  `samples/ProductionDeploymentDemo` running on Azure Container Apps
  (issuer + orders + Redis sidecar). The browser-driven 8-step interactive
  tour drives the full cross-service chain, with the typed
  `PqJwtFailureReason` on the wire (demo-only `EXPOSE_FAILURE_REASON=true`
  on the live OrdersApi).

### Environment quirks (still important)

- **Native ML-DSA/ML-KEM need OpenSSL 3.5+.** In the dev container, prefix
  test and benchmark runs with `LD_LIBRARY_PATH=/opt/conda/lib`. Without
  it, PQ tests skip (and the `linux-pq-required` CI lane fails on any skip).
- **NuGet publish:** the CI `NUGET_API_KEY` (on the `nuget-publish` GitHub
  environment) remains **invalid** — `preview.5` through `preview.8` were
  pushed **manually** with the key saved in `./nuget.key` (gitignored), so
  they lack the CI build-provenance attestation. Each affected
  `CHANGELOG.md` entry carries a transparency-note paragraph. The
  playground deploy secret (`AZURE_CREDENTIALS`) is healthy; the live demo
  deploy uses `az login` + `samples/ProductionDeploymentDemo/azure/deploy.ps1`
  manually.

## What's worth knowing right now

- **`docs/AUDIT-OUTREACH.md`** tracks the standards-body / audit-firm
  outreach. The X-Wing draft co-authors (Bas Westerbaan, Deirdre Connolly,
  Peter Schwabe) replied on 2026-06-05 endorsing our handling of the
  randomized-only ML-KEM constraint; a PR to formalise the guidance in
  X-Wing draft §5.4.1 is in flight, and we have an open ask to be listed in
  the Implementations appendix. `KNOWN-GAPS.md` was reframed accordingly.
- **`docs/SIGNPATH-APPLICATION.md`** and **`docs/OPENSSF-BADGE.md`** have
  pre-filled application material ready to submit (forms only — the work
  is done). Both are no-budget, high-signal credentials for the project.
- **`chatdemoresults.md` and `thisismeagainchatgpt.md`** are external
  review snapshots with "Resolution" sections at the bottom showing what
  was fixed. Future reviews can land alongside under their own names.
- **`gem.md`** is an early-preview review whose seven items were all
  implemented; the "Resolution" section cites the relevant code locations.
- **`VERSION-RECONCILIATION.md`** is a historical snapshot of the
  preview.1/preview.2 maturity-tier bump (kept for the suite-policy
  rationale it captures).

## Where the gates are

The `preview.*` suffix comes off when the construction has been
independently audited. The roadmap in
[`docs/ROADMAP-TO-1.0.md`](docs/ROADMAP-TO-1.0.md) names this as the
single gating concern. Three concrete moves to close that gate are
pre-written:

1. **Audit outreach** — `docs/AUDIT-OUTREACH.md` has draft letters
   (academic + commercial framings) and a ranked target list. Personalise
   and send.
2. **SignPath Foundation free OSS code signing** — application material
   is in `docs/SIGNPATH-APPLICATION.md`. Submit at
   <https://signpath.org/apply>. After approval, the release pipeline
   (`.github/workflows/release.yml` lines 142-164) automatically picks up
   the cert when `NUGET_SIGNING_CERT` is set on the `nuget-publish`
   environment.
3. **OpenSSF Best Practices badge** — application material is in
   `docs/OPENSSF-BADGE.md` with every criterion mapped to evidence in the
   repo. Submit at <https://www.bestpractices.dev/en/projects/new>.

## Quick commands

```bash
# full default suite (PQ-capable; opt-in timing test excluded)
LD_LIBRARY_PATH=/opt/conda/lib dotnet test --filter "Category!=Timing"

# opt-in timing-distribution probe (constant-time verify in c̃ region)
LD_LIBRARY_PATH=/opt/conda/lib dotnet test --filter Category=Timing

# version-sync check before any release
bash scripts/check-version-sync.sh

# mutation testing (~8 min on the expanded scope)
dotnet stryker

# tier-2 coverage-guided fuzz (multi-hour)
LD_LIBRARY_PATH=/opt/conda/lib fuzz/run.sh

# model-check the validator (needs Java + tla2tools.jar)
cd docs/formal && java -cp /path/to/tla2tools.jar tlc2.TLC PqJwtValidator.tla

# deploy / rebuild the live demo
cd samples/ProductionDeploymentDemo/azure && ./deploy.ps1 -ExtraCorsOrigins "https://demo.pqjwt.systemslibrarian.dev"
./rebind-hostname.ps1   # after any bicep redeploy
```

## Guardrails reminder (from CLAUDE.md)

Honesty over polish; fail-closed always; don't roll your own crypto (BCL
first, BouncyCastle only for X25519/SHA3); keep the surface small; every
doc footer ends with the faith line. Don't reintroduce
interop/"production-ready"/"audited" overclaims — this is an unaudited
**production-oriented preview**.

---

*To God be the glory — 1 Corinthians 10:31.*
