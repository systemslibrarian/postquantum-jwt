# HANDOFF — point a fresh Claude session here

This note captures the current state of the project for someone (or some
agent) picking it up cold. **Read `CLAUDE.md` first** (project guardrails),
then this file.

## Project state (as of 2026-07-05)

- **`PostQuantum.Jwt.AspNetCore` is frozen at 1.0.0** — superseded by
  [`PostQuantum.AspNetCore`](https://github.com/systemslibrarian/postquantum-aspnetcore)
  (its own repo, `repos/postquantum-aspnetcore`). The nuget.org package was
  deprecated + unlisted on 2026-07-05. Repo-side enforcement: `IsPackable=false`
  in its csproj, no pack/push steps in `release.yml` / `ci.yml`,
  `check-version-sync.sh` pins template refs to it at exactly 1.0.0, and
  `AddPqJwtBearer(...)` is `[Obsolete]` (`PQJWT100`, suppressed repo-wide in
  `Directory.Build.props`). **Do not add it back to the release pipeline.**
  Future releases push three packages: core, analyzers, templates. Open
  follow-up: migrate `templates/content/PqJwtWebApi` to `PostQuantum.AspNetCore`
  (entry point there is `AddPostQuantumJwtBearer(...)`; key-ring types renamed).
- **Releasing `1.0.0` — first stable release.** The version was bumped across
  all four packages (`PostQuantum.Jwt`, `PostQuantum.Jwt.AspNetCore`,
  `PostQuantum.Jwt.Analyzers`, `PostQuantum.Jwt.Templates`) from
  `1.0.0-preview.10` → `1.0.0`. The public API and v1 wire format are
  **unchanged** versus `preview.10`; a pre-release Gemini bug-catch added two
  small hardening fixes (exception-safe encryption-plaintext zeroing in
  `PqJwtBuilder`; oversized-token rejections now emit the `pqjwt.validations`
  failure metric — both in the `[1.0.0]` CHANGELOG entry, regression test in
  `PqJwtMetricsTests`). Otherwise this is a messaging + commitment change.
  **Key decision
  (2026-06-30):** the independent-audit gate to `1.0` was *removed
  deliberately* — an unfunded project is unlikely to obtain a formal review,
  so the missing audit is now reframed as a **permanent, documented
  limitation** rather than a release blocker. The framing across `README.md`,
  `KNOWN-GAPS.md`, `SECURITY.md`, and `docs/ROADMAP-TO-1.0.md` was rewritten
  accordingly ("production-oriented preview" → "production-quality library,
  not independently audited"). At this point the tag `v1.0.0` and the
  nuget.org publish of all four packages still need to be cut (see
  release steps below); the previous live release was `1.0.0-preview.10`.
  preview.9 hardened `InMemoryReplayCache` and `HttpPqJwtKeyRing` for
  concurrency / lifecycle (the latter now an `IHostedService` — consumers must
  register it as a hosted service). preview.10 then fixed two regressions on
  top: a case-sensitive `Authorization: Bearer` check in `PqJwtBearerHandler`
  (RFC 9110 §11.1) and the `VerifierDemo` sample missing the hosted-service
  registration from the preview.9 refactor.
- **All work is on `main`** (the maintainer does **not** use feature
  branches — commit and push directly to `main`).
- **Default test suite is green** across `PostQuantum.Jwt.Tests` (the
  fail-closed/library suite) and `PostQuantum.Jwt.Analyzers.Tests` (the
  PQJWT001/002 diagnostics suite); see the README for the live figure as
  new fail-closed tests land across previews. One opt-in
  timing-distribution test still runs via
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
- **NuGet publish — migrating to Trusted Publishing (OIDC).** The old CI
  `NUGET_API_KEY` was **invalid**, so `preview.5` through `preview.10` **and
  the `1.0.0` GA** were pushed **manually** with the key in `./nuget.key`
  (gitignored); those uploads lack the CI build-provenance attestation (each
  affected `CHANGELOG.md` entry carries a transparency note). As of 2026-06-30
  `release.yml`'s `publish` job was rewritten to use **NuGet Trusted
  Publishing**: it requests a short-lived key via `NuGet/login@v1` over GitHub
  OIDC (`id-token: write`), so there is no long-lived secret. **To make the
  next tagged release publish automatically, three one-time setup items are
  required:** (1) create the Trusted Publishing policy on nuget.org bound to
  `repo owner = systemslibrarian`, `repo = postquantum-jwt`,
  `workflow = release.yml`, `environment = nuget-publish`; (2) add a repo
  **variable** `NUGET_USER` = the nuget.org account username that owns the
  policy (Settings → Secrets and variables → Actions → Variables); (3) keep
  the `nuget-publish` environment's required reviewers for the manual gate.
  Until that policy + variable are in place, the `publish` job will fail at
  the `NuGet/login` step — the `./nuget.key` manual push remains the fallback.
  The `pack` job (build-provenance attestation + SBOM + SHA256SUMS) already
  runs on tag push regardless. The playground deploy secret
  (`AZURE_CREDENTIALS`) is healthy; the live demo deploy uses `az login` +
  `samples/ProductionDeploymentDemo/azure/deploy.ps1` manually.

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

**The `preview` suffix is gone as of `1.0.0`.** The independent audit is no
longer a release gate — it is a permanent, documented limitation (see the
decision banner in [`docs/ROADMAP-TO-1.0.md`](docs/ROADMAP-TO-1.0.md)). The
three moves below are still worth pursuing as post-1.0 credibility work, but
none of them blocks a release any more:

1. **Audit outreach (still open, no longer gating)** — `docs/AUDIT-OUTREACH.md`
   has draft letters (academic + commercial framings) and a ranked target
   list. If a review ever lands, ship its response as the appropriate SemVer
   release.
2. **SignPath Foundation free OSS code signing** — application material
   is in `docs/SIGNPATH-APPLICATION.md`. Submit at
   <https://signpath.org/apply>. After approval, the release pipeline
   (`.github/workflows/release.yml` lines 142-164) automatically picks up
   the cert when `NUGET_SIGNING_CERT` is set on the `nuget-publish`
   environment.
3. **OpenSSF Best Practices badge** — application material is in
   `docs/OPENSSF-BADGE.md` with every criterion mapped to evidence in the
   repo. Submit at <https://www.bestpractices.dev/en/projects/new>.

## To actually cut the `1.0.0` release

1. `bash scripts/check-version-sync.sh` — must pass (all strings at `1.0.0`).
2. `LD_LIBRARY_PATH=/opt/conda/lib dotnet test --filter "Category!=Timing"` — green.
3. Commit, then `git tag v1.0.0 && git push --tags`.
4. Pack + push all four packages (manually via `./nuget.key` until the CI
   `NUGET_API_KEY` is fixed — see the transparency note in `CHANGELOG.md`).
5. Cut the GitHub Release from the tag with the `1.0.0` CHANGELOG section.

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
