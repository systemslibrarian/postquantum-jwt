# OpenSSF Best Practices Badge — preparation checklist

The [OpenSSF Best Practices Badge](https://www.bestpractices.dev/) (formerly
Core Infrastructure Initiative Best Practices) is a self-certification that
an OSS project follows ~70 baseline practices spanning project basics, change
control, reporting, quality, security, and analysis. Achieving the **Passing**
tier is a low-cost, high-signal milestone that tells security-conscious
consumers and auditors the project takes its assurance seriously.

Apply at <https://www.bestpractices.dev/en/projects/new>. This document
inventories the criteria with current evidence so the form takes ~30 minutes
to fill out rather than a half-day of digging.

> Status: **draft, not yet submitted.** Submit and record the badge URL +
> percentage at the bottom of this file.

## Basics

| Criterion | Status | Evidence |
|---|:-:|---|
| `description_good` — project has a clear description | ✅ | `README.md` opening, `PostQuantum.Jwt.csproj` `<Description>` |
| `interact` — public discussion channel | ✅ | GitHub issues + Discussions (enable Discussions if not on) |
| `contribution` — explains how to contribute | ✅ | `CONTRIBUTING.md` |
| `contribution_requirements` — explains requirements (DCO/CLA, style) | ✅ | `CONTRIBUTING.md` |
| `license_location` — license file at a standard location | ✅ | `LICENSE` (MIT) at repo root |
| `floss_license` — uses an OSI-approved license | ✅ | MIT |
| `floss_license_osi` — license is OSI-approved | ✅ | MIT (OSI #MIT) |
| `documentation_basics` — basic docs on what it does and how to use | ✅ | `README.md`, `samples/`, [`docs/SPEC.md`](SPEC.md) |
| `documentation_interface` — describes API / external interface | ✅ | XML doc comments on every public member (`GenerateDocumentationFile=true`); SourceLink |
| `sites_https` — project/download/repo over HTTPS | ✅ | `github.com`, `nuget.org`, playground at `pqjwt.systemslibrarian.dev` are all HTTPS |
| `discussion` — discussion mechanism allows threading and persists | ✅ | GitHub Issues + Discussions |
| `english` — primary documentation in English | ✅ | All docs English |
| `maintained` — project is actively maintained | ✅ | Eight previews shipped 2026; recent commits on `main` |

## Change control

| Criterion | Status | Evidence |
|---|:-:|---|
| `repo_public` — repository is publicly accessible | ✅ | `github.com/systemslibrarian/postquantum-jwt` |
| `repo_track` — uses a version control system | ✅ | Git |
| `repo_interim` — interim versions are available | ✅ | Every commit on `main` is visible |
| `version_unique` — releases use unique version numbers | ✅ | SemVer `1.0.0-preview.N`; enforced by `scripts/check-version-sync.sh` |
| `version_semver` — uses SemVer or equivalent | ✅ | SemVer (`CHANGELOG.md` header) |
| `version_tags` — versions are tagged in VCS | ✅ | `v1.0.0-preview.N` annotated tags |
| `release_notes` — release notes for each release | ✅ | `CHANGELOG.md` (Keep-a-Changelog format) + `<PackageReleaseNotes>` in core csproj |
| `release_notes_vulns` — release notes call out fixed vulns | ✅ | Preview .6, .7, and .8 each cite the fail-closed security fix and surfacing layer |

## Reporting

| Criterion | Status | Evidence |
|---|:-:|---|
| `report_process` — describes how to report problems | ✅ | `CONTRIBUTING.md` + `README.md` issues section |
| `report_tracker` — uses an issue tracker | ✅ | GitHub Issues |
| `report_responses` — responses to issues / acknowledgement | ✅ | Active issue/PR responses on `main` history |
| `enhancement_responses` — responds to enhancement requests | ✅ | Discussion/PR history |
| `report_archive` — archived discussion is publicly readable | ✅ | GitHub archives issues/PRs permanently |
| `vulnerability_report_process` — private reporting mechanism documented | ✅ | `SECURITY.md` "Reporting a vulnerability" (GitHub Security Advisories) + `.well-known/security.txt` (RFC 9116) |
| `vulnerability_report_private` — supports private reports | ✅ | GitHub Security Advisories |
| `vulnerability_report_response` — acknowledgement target stated | ✅ | `SECURITY.md` "What we'll do" table (5 / 14 / 60-day targets) |

## Quality

| Criterion | Status | Evidence |
|---|:-:|---|
| `build` — builds from source | ✅ | `dotnet build` + `global.json` pinned SDK |
| `build_common_tools` — uses common build tools | ✅ | `dotnet` SDK |
| `build_floss_tools` — build tools are FLOSS | ✅ | .NET SDK is MIT |
| `test` — has at least one test suite | ✅ | 176 tests in `dotnet test`; opt-in timing probe via `--filter Category=Timing` |
| `test_invocation` — easy to invoke tests | ✅ | `dotnet test` |
| `test_most` — tests cover most of the code | ✅ | Stryker.NET mutation kill rate 71.43% raw / ~87% on behaviorally-meaningful mutations after filtering exception-message survivors — see [`docs/TESTING.md`](TESTING.md) |
| `test_policy` — policy for adding tests with new features | ✅ | `CLAUDE.md` "Tests must stay honest"; preview release-notes show every fix shipped with regression tests |
| `tests_are_added` — new tests are added with feature/fix PRs | ✅ | Recent history: preview .6 (FsCheck + invariants), .7 (regression test for duplicate-key fix), .8 (BoundaryTests for `exp` overflow) |
| `tests_documentation_added` — documentation updated with feature/fix | ✅ | Each preview updates `CHANGELOG.md` + `KNOWN-GAPS.md` + `docs/TESTING.md` |
| `warnings` — code warnings are reasonable | ✅ | `TreatWarningsAsErrors=true` on shipping projects |
| `warnings_fixed` — strict warnings enabled | ✅ | Compiler warnings are errors |
| `warnings_strict` — analyzer warnings on | ✅ | .NET analyzers + `PostQuantum.Jwt.Analyzers` for compile-time architecture enforcement |

## Security

| Criterion | Status | Evidence |
|---|:-:|---|
| `know_secure_design` — at least one maintainer knows secure design | ✅ | `SECURITY.md` threat model + `docs/PQ-JWT-AUDIT-PROMPT.md` audit rules + `docs/formal/PqJwtValidator.tla` model-checked spec |
| `know_common_errors` — at least one maintainer knows common implementation errors | ✅ | Fail-closed totality contract, signature-before-claims ordering, canonical base64url, AES-GCM tag pinning, header field ignorance — all explicitly tested and documented |
| `crypto_published` — uses standard, published cryptographic protocols | ✅ | ML-DSA-65 (FIPS 204), ML-KEM-768 (FIPS 203), X25519 (RFC 7748), AES-256-GCM (NIST SP 800-38D), SHA3-256 (FIPS 202), X-Wing combiner (`draft-connolly-cfrg-xwing-kem`) |
| `crypto_call` — calls reviewed/standard libraries | ✅ | .NET BCL + BouncyCastle only — `SECURITY.md` "Dependency rationale" |
| `crypto_floss` — crypto components are FLOSS | ✅ | BCL (MIT), BouncyCastle (MIT-style) |
| `crypto_keylength` — sufficient key length | ✅ | ML-DSA-65 NIST category 3; ML-KEM-768 NIST category 3; AES-256; X25519 |
| `crypto_working` — no broken/risky crypto algorithms | ✅ | No MD5, no SHA-1 for security purposes, no RC4, no DES |
| `crypto_weaknesses` — no algorithms with known weaknesses | ✅ | All primitives are current NIST / IETF recommendations |
| `crypto_pfs` — perfect forward secrecy where applicable | ✅ | Encrypted-token path uses ephemeral X-Wing KEM per token |
| `crypto_password_storage` — passwords stored securely | N/A | Library does not store passwords |
| `crypto_random` — uses cryptographic-strength PRNG | ✅ | `System.Security.Cryptography.RandomNumberGenerator` + BCL `MLKem` / `MLDsa` (OS CSPRNG) |
| `delivery_mitm` — protects against MITM in delivery | ✅ | HTTPS to GitHub + nuget.org; nuget.org repository signing |
| `delivery_unsigned` — does not deliver unsigned executables | ✅ | nuget.org repository signing today; SignPath author signing per [`SIGNPATH-APPLICATION.md`](SIGNPATH-APPLICATION.md) (in progress) |
| `vulnerabilities_fixed_60_days` — high/critical vulns fixed in 60 days | ✅ | `SECURITY.md` "What we'll do" commits to ≤60-day coordinated disclosure |
| `vulnerabilities_critical_fixed` — no unfixed publicly-known critical vulns | ✅ | None known |

## Analysis

| Criterion | Status | Evidence |
|---|:-:|---|
| `static_analysis` — uses static analysis | ✅ | .NET analyzers + GitHub CodeQL workflow (`.github/workflows/codeql.yml`) + `PostQuantum.Jwt.Analyzers` |
| `static_analysis_common_vulnerabilities` — checks for common vulns | ✅ | CodeQL "security-and-quality" suite |
| `static_analysis_fixed` — fixes critical static-analysis findings | ✅ | Strict warnings-as-errors; no known unaddressed CodeQL findings |
| `static_analysis_often` — runs static analysis on every commit / pre-release | ✅ | CodeQL CI runs on every push to `main` and on schedule |
| `dynamic_analysis` — uses dynamic analysis | ✅ | Tier 1 (FsCheck adversarial) + Tier 2 (SharpFuzz + libFuzzer) fuzz suites — `docs/TESTING.md` |
| `dynamic_analysis_unsafe` — uses an unsafe-memory dynamic analyzer | N/A | C# / .NET is memory-safe at the language level; `unsafe` not used |
| `dynamic_analysis_enable_assertions` — enables runtime assertions in tests | ✅ | xUnit `Assert.*` plus fail-closed totality assertions in fuzz suite |
| `dynamic_analysis_fixed` — fixes critical dynamic-analysis findings | ✅ | Tier 2 fuzz finding (duplicate-key JOSE header) → fixed in `1.0.0-preview.7`; Stryker mutation finding (`exp + skew` overflow) → fixed in `1.0.0-preview.8` |

## What's left before submitting

The checklist above shows the project is already at or near Passing on every
criterion. The submission itself is the action:

1. Visit <https://www.bestpractices.dev/en/projects/new>, log in with GitHub.
2. Enter the repository URL: `https://github.com/systemslibrarian/postquantum-jwt`.
3. Walk the form; for each criterion above, paste the "Evidence" cell value
   into the justification text box. The form auto-saves between sessions.
4. Submit when all required criteria are ✅.

Optional follow-ups for Silver / Gold tiers (each takes meaningful additional
work — Passing is the right first goal):

- **Silver:** requires a documented coding standard, signed-commit policy,
  reviewer-by-someone-other-than-the-author for merges, and 2-factor-auth for
  privileged accounts.
- **Gold:** adds reproducible builds (we already have `Deterministic=true`,
  `ContinuousIntegrationBuild=true`, and `EmbedUntrackedSources=true` —
  verifying byte-identical rebuilds across hosts is the missing step), a
  second cryptographic reviewer, and a published threat model in machine-
  readable form.

## Submission record

- Submitted: _pending_
- Project URL on bestpractices.dev: _pending_
- Passing tier percentage at submission: _pending_
- Badge URL: _pending_ (add `[![OpenSSF Best Practices](...badge.svg)](...project)` to README on success)

---

*To God be the glory — 1 Corinthians 10:31.*
