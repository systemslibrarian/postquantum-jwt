# Supply chain & install verification

A consumer-facing summary of the provenance signals that ship with every
PostQuantum.Jwt release, and the exact commands to verify them yourself. Pair
with [`docs/RELEASE.md`](RELEASE.md) (the maintainer-side release process)
and [`docs/TESTING.md`](TESTING.md) (what is tested in repo).

Honest framing: there are real provenance signals here, and there are real
gaps (notably author code signing). This page covers both — see "What's
deliberately not signed yet" below.

## What each release ships

| Signal | Where | What it proves |
|---|---|---|
| **GitHub build-provenance attestation** (SLSA-style, `actions/attest-build-provenance@v4`) | One per `.nupkg` and one for the SBOM | The artifact was produced by *this* repository's release workflow at a specific commit, attested by GitHub's OIDC identity. |
| **CycloneDX SBOM embedded in the `.nupkg`** (`bom.json` at the package root) | Inside `PostQuantum.Jwt.<version>.nupkg` | The exact dependency graph of the package. Inspectable directly from nuget.org without unpacking. |
| **Top-level CycloneDX SBOM** | `artifacts/bom.json` on the GitHub release | The library's dependency graph at release time, separately attested. |
| **`SHA256SUMS.txt`** | GitHub release artifacts | SHA-256 of every `.nupkg`, `.snupkg`, and `bom.json`. |
| **`.snupkg` symbol packages + SourceLink** | Adjacent to each main `.nupkg` on nuget.org | Step into library source from your debugger directly to the commit on GitHub. SourceLink is wired via `Microsoft.SourceLink.GitHub`. |
| **Deterministic build** | `Directory.Build.props` sets `<Deterministic>true</Deterministic>`, `<ContinuousIntegrationBuild>true</ContinuousIntegrationBuild>`, `<EmbedUntrackedSources>true</EmbedUntrackedSources>` | Removes machine-specific build inputs so a rebuild from the same commit at the same SDK version produces the same bytes. |
| **nuget.org repository signature** | Applied automatically when nuget.org accepts the upload | Cryptographic proof that the package on the gallery is the one that was uploaded. |
| **Pinned compile-time analyzers** (consumer-side) | Opt-in via `PostQuantum.Jwt.Analyzers` (PQJWT001, PQJWT002) | Roslyn-enforced architectural boundaries in *your* code — catches header-trust and per-call validator construction at compile time. |

## Verifying what you just installed

`<version>` below is whatever you installed — for example `1.0.0-preview.9`.

### 1. Build provenance (every `.nupkg`)

```bash
# Download the .nupkg you installed (NuGet keeps a cache under
# ~/.nuget/packages/postquantum.jwt/<version>/postquantum.jwt.<version>.nupkg)
# or fetch directly:
curl -sLO https://www.nuget.org/api/v2/package/PostQuantum.Jwt/<version>

gh attestation verify PostQuantum.Jwt.<version>.nupkg \
    --repo systemslibrarian/postquantum-jwt
```

A passing run prints `verified` and shows the workflow file
(`.github/workflows/release.yml`), the commit SHA, and the workflow run that
built the package. The same command works against `.AspNetCore.nupkg`,
`.Analyzers.nupkg`, and `.Templates.nupkg`.

### 2. Embedded CycloneDX SBOM

A `.nupkg` is a zip file. The SBOM lives at the root:

```bash
unzip -p PostQuantum.Jwt.<version>.nupkg bom.json | jq .
```

Inspect `components` for the full transitive dependency list. No
out-of-band tools needed.

### 3. SHA-256 of the artifacts

Each GitHub release attaches an `artifacts/SHA256SUMS.txt`. After downloading
the release's `.nupkg` and `SHA256SUMS.txt` together:

```bash
sha256sum -c SHA256SUMS.txt
```

This is the same hash that NuGet computed during the workflow's pack step.
The SHA256SUMS file itself is covered by the SBOM attestation.

### 4. nuget.org repository signature

NuGet's own client verifies the repository signature on restore by default,
but you can confirm explicitly with the NuGet CLI:

```bash
nuget verify -All PostQuantum.Jwt.<version>.nupkg
```

This confirms the upload to nuget.org was not tampered with in transit or at
rest in the gallery.

### 5. SourceLink + symbols (debug-time)

The companion `.snupkg` (uploaded automatically with each push) plus
SourceLink lets you step from a frame inside `PqJwtValidator.Validate` into
the exact source line on GitHub. In Visual Studio / Rider / VS Code: ensure
"Enable Source Link support" and "Enable .NET Framework source stepping" are
on; under the symbol server settings, nuget.org symbol server (`https://symbols.nuget.org/download/symbols`)
is the default and serves these.

### 6. Build provenance for the SBOM itself

The SBOM gets its own attestation, separately verifiable:

```bash
gh attestation verify bom.json \
    --repo systemslibrarian/postquantum-jwt
```

This matters if you ingest SBOMs into a downstream supply-chain inventory and
need to attest provenance separately from the package.

## CI workflows that produce these signals

- [`.github/workflows/release.yml`](../.github/workflows/release.yml) — packs
  all four `.nupkg`, generates the top-level SBOM, writes `SHA256SUMS.txt`,
  emits the two build-provenance attestations, and pushes to nuget.org via the
  manually-approved `nuget-publish` GitHub Environment.
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — the gate every
  release passes through: build, 144-test suite, version-sync check.
- [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) — static
  security analysis on every push.
- [`.github/dependabot.yml`](../.github/dependabot.yml) — pinned dependency
  updates with security advisory tracking.

## What's deliberately not signed yet

Honesty over polish, per the project's stated stance:

- **No author code-signing certificate.** A code-signing cert from a CA would
  cryptographically tie the package to "Paul Clark, the author" in addition to
  the existing "GitHub workflow in this repo" provenance attestation.
  Currently absent; a free-for-OSS path via the SignPath Foundation is noted
  in [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).
- **No third-party independently-rebuilt bit-for-bit comparison.** The build
  is deterministic and would in principle reproduce, but no external party has
  rebuilt and posted a hash match. If you do this, please open an issue with
  the results — we'd link it from here.
- **No SLSA Level 3+ claim.** What's emitted is a SLSA-style build-provenance
  attestation via `actions/attest-build-provenance@v4`, which covers the
  attestation half of a SLSA story but does not by itself constitute a
  full SLSA level claim.

## When you find a tampered package

If `gh attestation verify` fails on a `.nupkg` claimed to be from this
repository, or `nuget verify` fails, **do not install or deploy that
artifact**. Report it via [`SECURITY.md`](../SECURITY.md) — that channel
exists for exactly this.

---

*To God be the glory — 1 Corinthians 10:31.*
