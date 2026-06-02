# Release process

A short, opinionated checklist for cutting a PostQuantum.Jwt release. The goal
is that every artifact we publish is traceable, reproducible, and matches its
documentation exactly — for a cryptographic library that is the bare minimum.

## Pre-release checklist

Run this list before pushing the version tag. CI enforces the boxed items;
the un-boxed items are a human review.

- [ ] **Bump `<Version>`** in lockstep across all four packages:
      `src/PostQuantum.Jwt`, `src/PostQuantum.Jwt.AspNetCore`,
      `templates/PostQuantum.Jwt.Templates`, and
      `src/Analyzers/PostQuantum.Jwt.Analyzers` — plus the `PostQuantum.Jwt*`
      `<PackageReference>`s inside the scaffolded template content.
- [x] **Version strings are in sync** across the library `.csproj`, `README.md`
      (the `dotnet add package` snippet *and* the `<PackageReference>` snippet),
      the `CHANGELOG.md` heading, the templates package + its scaffolded content
      references, and the analyzers package. Enforced by
      `scripts/check-version-sync.sh`, which runs on every push, pull request,
      and release tag.
- [ ] **CHANGELOG.md** has a section for the new version that describes
      `Added` / `Changed` / `Fixed` / `Security` deltas honestly. Update the
      `[Unreleased]` and `[<version>]` compare-links at the bottom.
- [ ] **`PackageReleaseNotes` in the `.csproj`** points at the
      `CHANGELOG.md` / `KNOWN-GAPS.md` URLs and gives a one-paragraph summary
      of the delta.
- [ ] **`KNOWN-GAPS.md`** "Last reviewed for" is the new version, and any
      newly-discovered gap is recorded there.
- [ ] **`SECURITY.md`** "Supported versions" table marks the new version as
      supported and earlier previews as superseded.
- [x] **`dotnet build -c Release`** is zero warnings. Compiler warnings are
      errors; analyzer hints (CAxxxx) stay warnings but the build still goes
      through with no analyzer noise in expected builds.
- [x] **`dotnet test -c Release`** is 100% green on Windows with **zero
      skipped tests**. The CI Windows lane fails the run if any PqcFact
      reports skipped — Linux skips are allowed only because some runners
      lack OpenSSL 3.5+; cryptographic assurance lives in the Windows lane.
- [x] **`dotnet pack`** produces all four packages — `PostQuantum.Jwt` and
      `PostQuantum.Jwt.AspNetCore` (each with a `.snupkg` symbols package),
      `PostQuantum.Jwt.Templates` (a `dotnet new` content package), and
      `PostQuantum.Jwt.Analyzers` (an analyzers-only package) — and the local
      consumer round-trip (install into a fresh project from a local feed and
      exercise sign / sign+encrypt / fail-closed) passes.
- [ ] **Manual smoke** — install the freshly packed `.nupkg` into a throwaway
      project and exercise the README's quick-start. Catches packaging-only
      regressions that don't show up in the in-repo tests.

## Cutting the release

1. Commit the version bump + changelog entry on `main`.
2. Push the tag:
   ```
   git tag v<version>
   git push origin v<version>
   ```
3. The `Release` workflow will:
   - run `scripts/check-version-sync.sh`
   - verify the tag (`v<version>`) matches `<Version>` in the `.csproj`
   - build + test
   - `dotnet pack` **all four** packages (`PostQuantum.Jwt`,
     `PostQuantum.Jwt.AspNetCore`, `PostQuantum.Jwt.Templates`,
     `PostQuantum.Jwt.Analyzers`) and generate a CycloneDX SBOM (`bom.json`) for
     the library's dependency graph
   - write `artifacts/SHA256SUMS.txt` covering the `.nupkg`, `.snupkg`,
     and `bom.json`
   - emit GitHub build-provenance attestations for **both** the `.nupkg`
     and the SBOM
   - wait on the `nuget-publish` GitHub Environment for manual approval
4. **Approve** the deployment in the GitHub Actions UI when ready. The
   workflow's `publish` job pushes to nuget.org with the API key stored on
   that environment.

## Verifying a published release

Anyone — including you, six months later — can verify that the `.nupkg` on
nuget.org came from this repository and was built by the release workflow:

```
gh attestation verify PostQuantum.Jwt.<version>.nupkg \
    --repo systemslibrarian/postquantum-jwt
```

This is **not** an author code-signing signature (we don't ship one yet —
tracked in `KNOWN-GAPS.md`), but it is a cryptographically verifiable
statement from GitHub that the artifact was produced by the workflow in this
repository at the given commit.

## Trust signals the workflow does *not* provide

Be honest about what is missing:

- **Author code signing.** No author-issued code-signing certificate yet.
  nuget.org applies its own repository signing on push.
- **Reproducible bit-for-bit rebuild from source.** The build is deterministic
  (`Deterministic=true`, `EmbedUntrackedSources=true`, `ContinuousIntegrationBuild=true`)
  but no third party has independently rebuilt and compared hashes.

When any of these change, update this document and the corresponding
`KNOWN-GAPS.md` entry in the same commit.

---

*To God be the glory — 1 Corinthians 10:31.*
