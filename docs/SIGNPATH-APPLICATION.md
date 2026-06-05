# SignPath Foundation OSS code-signing application — supporting material

The [SignPath Foundation](https://signpath.org/) provides **free authenticode
code signing** to open-source projects via the
[Free Code Signing program](https://signpath.org/apply). This document
collects the application material for PostQuantum.Jwt so the form at
<https://signpath.org/apply> can be filled out in a single sitting, and so the
record exists in the repo for future maintainers.

> Status: **draft, not yet submitted.** Submit at <https://signpath.org/apply>
> and link the application ID + outcome at the bottom of this file once heard
> back.

## Why PostQuantum.Jwt fits the OSS program

The Free Code Signing program is for OSS projects that ship **signed
artifacts** as part of their normal release flow. PostQuantum.Jwt qualifies:

- **Open source**, MIT licensed — `LICENSE` in repo root.
- **Mature release flow** — tag-driven CI in `.github/workflows/release.yml`
  packs four NuGet artifacts (`PostQuantum.Jwt`, `PostQuantum.Jwt.AspNetCore`,
  `PostQuantum.Jwt.Analyzers`, `PostQuantum.Jwt.Templates`) with embedded SBOM,
  SHA-256 checksums, and GitHub OIDC-backed build-provenance attestation.
- **Repository signature already in place via nuget.org** — every published
  `.nupkg` carries nuget.org's repository signature. Author signing through
  SignPath would add the *origin* signature on top, raising the bar against
  supply-chain attacks targeting our consumers specifically.
- **Security-relevant cryptographic library** — a hybrid post-quantum JWT
  library where consumers' authentication-and-confidentiality decisions depend
  on trusting the published bytes are what we built.

## Application form fields

| Field | Value |
|---|---|
| Project name | PostQuantum.Jwt |
| Project website | <https://github.com/systemslibrarian/postquantum-jwt> |
| Live playground | <https://pqjwt.systemslibrarian.dev> |
| License | MIT (see `LICENSE`) |
| Primary language | C# / .NET 10 |
| Maintainer | Paul Clark (`@systemslibrarian` on GitHub) |
| Contact email | (use the address on the GitHub profile) |
| Time zone | (maintainer's local) |
| Has signed releases today? | Repository signature only (nuget.org); no author signature yet |
| Release cadence | Tag-driven, currently ~1 preview every 1–4 weeks |
| Build platform | GitHub Actions, `ubuntu-latest` runners, `actions/setup-dotnet@v5` |
| Artefacts to sign | Four `.nupkg` files per release (see "Packages" below) |
| Signing tool | `dotnet nuget sign` (already wired in `release.yml` lines 142–164, gated on `NUGET_SIGNING_CERT` secret) |

### Packages

| Package ID | Purpose |
|---|---|
| `PostQuantum.Jwt` | Main library — JOSE-style PQ tokens |
| `PostQuantum.Jwt.AspNetCore` | ASP.NET Core bearer authentication handler |
| `PostQuantum.Jwt.Analyzers` | Roslyn analyzers (PQJWT001, PQJWT002) |
| `PostQuantum.Jwt.Templates` | `dotnet new` project templates (`pqjwt-webapi`, `pqjwt-console`) |

### Why the project benefits from code signing

1. **Identity provenance.** nuget.org's repository signature proves the
   package on the gallery is the package that was uploaded; it does not
   prove the package was built by us. An author signature ties the bytes
   to a verifiable identity (SignPath's certificate via the SignPath
   Foundation) and lets consumers and auditors verify that the
   maintainer's build pipeline produced the artefact, not a compromised
   intermediary.
2. **Defense-in-depth against nuget.org compromise.** A hypothetical
   gallery compromise that swapped the `.nupkg` without our knowledge would
   invalidate the author signature; consumers using strict client policies
   would fail-closed.
3. **OS-level trust signals.** Authenticode-signed packages flow through
   Windows / .NET trust pipelines without warnings, removing one source of
   friction for security-conscious consumers.
4. **Roadmap commitment.** Cited as a known gap in
   [`KNOWN-GAPS.md`](../KNOWN-GAPS.md) since `1.0.0-preview.5`; addressing
   it is on the explicit roadmap to `1.0.0`.

## Wiring after approval

The CI workflow is already structured for SignPath integration — only secret
configuration is missing. After approval:

1. SignPath issues a certificate handle; configure the corresponding GitHub
   Actions secret in the `nuget-publish` environment.
2. The existing `.github/workflows/release.yml` step at lines 142–164
   ("Author code-sign packages (if certificate available)") already invokes
   `dotnet nuget sign` when `NUGET_SIGNING_CERT` is present and skips silently
   when it isn't. Switching `NUGET_SIGNING_CERT` from absent → SignPath-issued
   activates author signing on the next tag push.
3. The published `.nupkg` files then carry both signatures (author = SignPath
   identity, repository = nuget.org). `dotnet nuget verify` will confirm both.
4. Document the certificate identity + thumbprint in
   [`docs/SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) so consumers can pin against it.

## What to include if SignPath asks for technical due-diligence

- The reviewer-facing test pyramid: [`docs/TESTING.md`](TESTING.md).
- The security posture and reporting policy: [`SECURITY.md`](../SECURITY.md).
- The known-gaps inventory (what we do not yet do): [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).
- The transparent release notes — every preview's `CHANGELOG.md` entry
  includes a "published manually via `dotnet nuget push`" transparency note
  when the CI key was invalid; this is the same honesty we'll bring to the
  signing key.

## Submission record

- Application submitted: _pending_
- Application ID: _pending_
- Reviewer notes: _pending_
- Outcome / certificate handle: _pending_

---

*To God be the glory — 1 Corinthians 10:31.*
