# Roadmap to 1.0

What it takes for PostQuantum.Jwt to drop the `preview` suffix and ship as
`1.0.0`. This consolidates the framing scattered across
[`README.md`](../README.md), [`KNOWN-GAPS.md`](../KNOWN-GAPS.md), and
[`SECURITY.md`](../SECURITY.md) so a reviewer asking "when is 1.0?" has one
page to read.

The honest summary: the `preview` suffix tracks the *pending independent
audit*, not API churn. The public API and wire format are held stable across
the `1.0.0-preview.*` series — no breaking changes are planned before `1.0.0`,
though a security review could still force one.

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

## What blocks 1.0

In rough priority order:

1. **Independent cryptographic audit.** The single load-bearing blocker.
   The construction has not been independently reviewed. The `preview`
   suffix reflects this gap; removing the suffix without an audit would
   misrepresent the assurance posture. See
   [`KNOWN-GAPS.md`](../KNOWN-GAPS.md) under "Cryptography → No external
   audit". An audit could force a one-time wire-format or API change, in
   which case we'd cut a `1.0.0-rc.1` first and ship the audit response in
   that release.
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
1.0.0-preview.N   ← preview series; API + wire stable, awaiting audit
        │
        ▼
1.0.0-rc.1        ← cut after the audit response is incorporated
        │
        ▼
1.0.0             ← independent audit complete; semver applies from here
        │
        ▼
1.0.x, 1.1.x …    ← semver: PATCH for fixes, MINOR for additive surface
```

There is no public target date for 1.0. The audit is the gate; everything
upstream of it is honest preview maturity work.

## Tracking

A `1.0` GitHub milestone collects the audit-related issues. Anything
labelled `1.0-blocker` must be closed before the `rc.1` tag is pushed.

---

*To God be the glory — 1 Corinthians 10:31.*
