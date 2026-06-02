# Version Reconciliation — 2026-06-01

## New suite version: 1.0.0-preview.1

Both packages in this repository have been raised from `0.3.0-preview.1` to
`1.0.0-preview.1` in exact lockstep. This is a maturity-tier bump only — no
new algorithm suite, no algorithm agility. The `preview.N` suffix continues
to carry the "not independently audited" caveat; the leading `1.0` does not.

## Update — 1.0.0-preview.2 (2026-06-02)

Both packages were raised again, `1.0.0-preview.1` → `1.0.0-preview.2`, in the
same exact lockstep. This is an **additive** preview (validation metrics +
`PqJwtFailureReason` typed reasons; the crypto core and fail-closed behavior are
unchanged), plus the new `PostQuantum.Jwt.Templates` package, which pins
`PostQuantum.Jwt = 1.0.0-preview.2`. `scripts/check-version-sync.sh` now also
guards the template package version and its scaffolded `PackageReference`s, so
all version strings — both packages, README, CHANGELOG, and the templates — stay
in lockstep.

## Changes applied

### Version strings

- `src/PostQuantum.Jwt/PostQuantum.Jwt.csproj` — `<Version>` 0.3.0-preview.1 → 1.0.0-preview.1
- `src/PostQuantum.Jwt.AspNetCore/PostQuantum.Jwt.AspNetCore.csproj` — `<Version>` 0.3.0-preview.1 → 1.0.0-preview.1
- `README.md` — status line and both install snippets updated to 1.0.0-preview.1
- `CHANGELOG.md` — new `[1.0.0-preview.1]` entry added; `[Unreleased]` items folded into it
- `KNOWN-GAPS.md` — "Last reviewed for" pointer bumped to 1.0.0-preview.1
- `SECURITY.md` — supported-versions table bumped to 1.0.0-preview.1; older 0.x previews marked superseded

### Inter-package dependency constraints

The suite-level policy was:

> - `PostQuantum.Jwt` must pin `PostQuantum.Cryptography = 1.0.0-rc.1`
> - `PostQuantum.Jwt.AspNetCore` must pin `PostQuantum.Jwt = 1.0.0-preview.1`

Applied **only where actually referenced**:

- **`PostQuantum.Cryptography` is NOT a dependency of `PostQuantum.Jwt` in
  this repository.** `PostQuantum.Jwt`'s only third-party crypto dependency
  is `BouncyCastle.Cryptography` (used solely for X25519 and SHA3-256 inside
  the X-Wing combiner). ML-KEM-768 and ML-DSA-65 come from the native .NET
  BCL. No `PackageReference Include="PostQuantum.Cryptography"` exists today
  and none was added — fabricating a dependency to satisfy a suite-wide
  policy would violate this repo's "native BCL first; a new third-party dep
  needs a written justification in `SECURITY.md`" rule (`CLAUDE.md`). If a
  future release of `PostQuantum.Jwt` actually consumes
  `PostQuantum.Cryptography`, the pin will be added at that time.
- **`PostQuantum.Jwt.AspNetCore` → `PostQuantum.Jwt`** is expressed today as
  a `<ProjectReference>` to the sibling project. NuGet rewrites this into a
  pinned `PackageReference` at pack time using the referenced project's
  `<Version>` — so bumping `PostQuantum.Jwt` to `1.0.0-preview.1` *is* what
  pins `PostQuantum.Jwt.AspNetCore`'s dependency to `1.0.0-preview.1`. An
  explicit `<PackageReference Version="…" />` override would risk drift
  between the project and package graphs and was deliberately not added.

## Maturity-tier audit

**No package in this repository advertises more maturity than what it
depends on.**

- **`PostQuantum.Jwt` (1.0.0-preview.1)** — no `PostQuantum.Cryptography`
  dependency exists in this repo, so there is no cross-package maturity
  gradient to violate here. If we treat the suite-level reference
  `PostQuantum.Cryptography 1.0.0-rc.1` as the comparison: in SemVer 2.0
  pre-release ordering, **`preview` sorts below `rc` sorts below the GA
  release** (`1.0.0-preview.1` < `1.0.0-rc.1` < `1.0.0`). So
  `PostQuantum.Jwt (1.0.0-preview.1)` sits at or below `PostQuantum.Cryptography
  (1.0.0-rc.1)` — `preview < rc`, which is correct.
- **`PostQuantum.Jwt.AspNetCore` (1.0.0-preview.1)** depends on
  `PostQuantum.Jwt (1.0.0-preview.1)` — exact lockstep, equal tier.

## What remains honest after the bump

- README still leads with "Preview software. Not for production use."
- README now also leads with an above-the-fold "Read this first" disclosure
  that the `alg`/`enc` identifiers (`ML-DSA-65`, `X-Wing`, `A256GCM` over
  nested JWT) are **not** IANA-registered and tokens will not validate in
  generic JWT tooling.
- `KNOWN-GAPS.md` and `SECURITY.md` remain authoritative; nothing in them is
  softened by the version bump.
- The two existing JWT-specific caveats remain prominent in both the README
  and the package release notes:
  1. **Non-IANA-registered identifiers** mean these tokens do **not** interop
     with standard JWT tooling.
  2. **Randomized-encapsulation KAT gap** — the BCL `MLKem.Encapsulate`
     exposes no derandomized entry point, so the ML-KEM encapsulation path
     is covered by round-trip and decapsulation KATs (plus a new 64-iteration
     statistical sanity test) rather than a true encapsulation KAT. The
     X-Wing combiner direction and the X25519 ephemeral half *can* now be
     exercised deterministically through an internal `IXWingDeterministicCoins`
     test seam — production code never reaches that path; the seam is
     `internal` and reachable only via `InternalsVisibleTo("PostQuantum.Jwt.Tests")`.

---

*To God be the glory — 1 Corinthians 10:31.*
