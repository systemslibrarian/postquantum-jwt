# Roadmap to 1.0

> **DECISION — 2026-06-30: `1.0.0` shipped without an independent audit.**
> This document originally defined an external cryptographic audit as the
> single gate to dropping the `preview` suffix. That gate was **removed
> deliberately** at `1.0.0`. The reasoning: as an unfunded open-source project
> we are unlikely to obtain a formal third-party review (outreach status in
> [`docs/AUDIT-OUTREACH.md`](AUDIT-OUTREACH.md)), and staying in perpetual
> `preview` hurt adoption while implying the audit gap by a version suffix
> rather than stating it plainly. The library now ships stable, with the
> **lack of an independent audit reframed as a permanent, documented
> limitation** (see [`KNOWN-GAPS.md`](../KNOWN-GAPS.md) → "No external audit"
> and [`SECURITY.md`](../SECURITY.md)). The rest of this page is kept as the
> record of what "stable" was defined to mean and what was — and was not —
> treated as a blocker.

The historical framing below is preserved for context. Where it says the
`preview` suffix "tracks the pending audit," read that as the framing that was
in force *before* the 2026-06-30 decision above.

The honest summary: the public API and wire format were held stable across
the `1.0.0-preview.*` series — no breaking changes landed before `1.0.0`.

## What's already stable

These have been held stable across the preview series and are commitments
for `1.0.0`:

- **Public API surface.** `PqJwtBuilder`, `PqJwtValidator`,
  `PqJwtValidationParameters`, `PqJwtValidationResult`, `PqJwtException`,
  `PqJwtValidationException`, `PqJwtFailureReason`, `PqJwtAlgorithms`,
  `IPqJwtReplayCache`, `InMemoryReplayCache`. XML doc comments on every
  public member; `EnablePackageValidation=true` catches accidental API breaks
  on every pack.
- **Wire format.** The v1 token profile — `alg=ML-DSA-65` for signing,
  `alg=X-Wing` + `enc=A256GCM` for encryption — is normative in
  [`docs/SPEC.md`](SPEC.md). Builder-minted tokens from preview.3 onward
  round-trip through preview.7 unchanged; the encrypted-path hardening in
  preview.6 and the duplicate-key fix in preview.7 only tightened
  *acceptance*, never *production*.
- **Fail-closed totality contract.** Only `PqJwtException` (and its
  subclasses, primarily `PqJwtValidationException`) may escape
  `PqJwtValidator.Validate(...)`. Coverage-guided fuzz found one
  totality-violation bug (duplicate JSON header keys, fixed in preview.7);
  the Stryker-driven boundary tests found another (`exp + skew` overflow
  at `DateTimeOffset.MaxValue`, fixed post-preview.7). Both are now
  regression-locked. See [`docs/TESTING.md`](TESTING.md).
- **Observability shape.** The `PostQuantum.Jwt` meter, the
  `pqjwt.validations` counter, and the bounded `reason` tag (driven by the
  `PqJwtFailureReason` enum) are stable.
- **`kid`-based key rotation.** `SignatureKeyResolver` + `kid` is the
  agility surface. We do not — and will not in 1.0 — read `jku`/`jwk`/
  `x5u`/`x5c` from the token's header to select a key. See `RedTeamScenarios.cs`.

## What was treated as blocking 1.0 (historical)

In rough priority order, as defined before the 2026-06-30 decision:

1. **Independent cryptographic audit.** *Originally the single load-bearing
   blocker — resolved by decision, not by an audit.* The construction has
   still not been independently reviewed; rather than hold `1.0` indefinitely
   for a review an unfunded project is unlikely to obtain, the project shipped
   `1.0.0` stable and **reframed the missing audit as a permanent, documented
   limitation** (see the decision banner above and
   [`KNOWN-GAPS.md`](../KNOWN-GAPS.md) → "No external audit"). If a review
   later happens and forces a wire-format or API change, that ships as the
   appropriate SemVer bump (and would be MAJOR if it breaks the v1 format).
2. **CI release-pipeline parity.** preview.7 was the first end-to-end CI
   publish since preview.3 — it surfaced (and patched) a gap in
   `release.yml` (it only pushed `PostQuantum.Jwt` and
   `PostQuantum.Jwt.AspNetCore`, not the analyzers and templates). Both
   the fix and the recovery for preview.7 shipped; 1.0 wants one clean
   end-to-end CI publish with all four packages, including the
   build-provenance attestation, to demonstrate the pipeline.
3. **Tier 2 fuzz running in CI.** The SharpFuzz + libFuzzer Tier 2 target
   is operational locally (it found the duplicate-key bug). 1.0 wants
   it running on a schedule in GitHub Actions, the same way `fuzz.yml`
   runs the FsCheck Tier 1 nightly.

## What is *not* a blocker

These are deliberate non-goals and will remain so in 1.0:

- **Algorithm agility / composite signatures.** One suite (ML-DSA-65 +
  X-Wing + A256GCM). See `docs/adr/0001-algorithm-agility.md` and the
  composite-signatures entry in [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).
- **Token compression (`zip:DEF`) / Compact Mode.** Documented in
  KNOWN-GAPS with the size/CPU math. Revisitable only if a real consumer
  hits a concrete header-size limit.
- **JOSE/IANA standardisation of the X-Wing key-management profile.**
  This is a draft-`connolly-cfrg-xwing-kem` consumer, not a standards
  contribution. Tokens are intentionally **not** interoperable with
  generic JWT tooling. See README → "Standards and interoperability status".
- **General OAuth/OIDC replacement.** Out of scope. The library is for
  controlled issuer/verifier systems.
- **Author code-signing certificate.** Tracked in
  [`docs/SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) and KNOWN-GAPS. The SignPath
  Foundation path is noted; absence is not a 1.0 blocker (the existing
  GitHub build-provenance attestation + nuget.org repository signature
  cover the supply-chain story for now).

## Release cadence pattern

```
1.0.0-preview.N   ← preview series; API + wire stable (what actually happened)
        │
        ▼
1.0.0             ← shipped 2026-06-30 without an audit; semver applies from here.
        │            The no-audit gap is a permanent, documented limitation.
        ▼
1.0.x, 1.1.x …    ← semver: PATCH for fixes, MINOR for additive surface
```

The originally-planned `1.0.0-rc.1` step (cut after an audit response) was
dropped along with the audit gate. `1.0.0` shipped directly from
`1.0.0-preview.10` with no code change. If an independent review ever happens,
its response ships as the appropriate SemVer release.

## Tracking

A `1.0` GitHub milestone collects the audit-related issues. Anything
labelled `1.0-blocker` must be closed before the `rc.1` tag is pushed.

---

*To God be the glory — 1 Corinthians 10:31.*
