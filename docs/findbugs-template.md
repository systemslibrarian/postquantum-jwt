# Whole-repo bug audit prompt

> **What this file is.** The prompt the maintainer hands to an external
> reviewer (a person, an AI assistant, or both) when requesting a
> structured bug audit of the entire PostQuantum.Jwt repository. It
> exists so every round of external review produces output the maintainer
> can act on the same day without translating between formats.
>
> **What this file is not.** The narrower validator-specific checklist
> lives at [`PQ-JWT-AUDIT-PROMPT.md`](PQ-JWT-AUDIT-PROMPT.md). Use that
> when reviewing only the fail-closed token-validation path. Use **this**
> one when reviewing every line of production code in the repo.
>
> **How to use it.** Copy the entire body below into the new chat /
> ticket / engagement. Do not summarise. The audit's quality depends on
> the reviewer following the structure verbatim — every dropped section
> visibly lowers the signal of the resulting report.

---

## Task

Perform an **exhaustive, file-by-file bug audit** of the `postquantum-jwt`
repository at <https://github.com/systemslibrarian/postquantum-jwt>.

Read every source file in the three areas listed below. Do not sample.
Do not skip files. Samples are first-class production-influencing code —
people copy them verbatim — so a bug in a sample is a shipped bug.

The deliverable is a single Markdown file conforming to the **Output
contract** at the bottom of this prompt.

## Begin by listing the files you will read

Before any prose, output the three inventory tables (one per scope area)
from the **Output contract** below, with the file column populated and
the "Bugs" column blank. This commits the reviewer to full coverage and
makes selective reading visible to the maintainer.

## Scope (read these globs in full, in this order)

1. **Core library** — `src/**/*.cs`
   (`src/PostQuantum.Jwt/`, `src/PostQuantum.Jwt.AspNetCore/`, `src/Analyzers/`)
2. **Samples** — `samples/**/*.cs`
   (every sample under `samples/`, including the full
   `samples/ProductionDeploymentDemo/` tree)
3. **VS Code extension** — `tools/vscode/src/**/*.ts`
   (extension host, webview, decoder, inspector)

**Out of scope** — do not produce findings against:

- `tests/**` — has its own conventions; flag missing coverage as part of
  the relevant production finding instead
- `**/bin/**`, `**/obj/**` — build output
- `fuzz/corpus/**` — libFuzzer-discovered inputs, not source
- `samples/PqJwtPlayground/wwwroot/lib/**` — vendored client assets
- Markdown documentation under `docs/` — audit docs separately if asked

## Evidence requirements (mandatory)

Every reported finding must be **proven**. A claim without proof is
rejected outright. Each finding carries this inline block placed directly
above the offending line of the most relevant file:

```text
// BUG: <one-sentence description of the wrong behaviour>
// PROOF: <a specific input → expected vs. actual trace with values at
//         each step; OR the broken contract cited by file:line in this
//         repo or by RFC / FIPS / draft section number; OR a
//         counterexample demonstrating an invariant violation>
// TRIGGER: <precise conditions: input, state, interleaving, edge case>
// SEVERITY: <Critical | High | Medium | Low | Info> — <one-clause
//          threat model: who controls what, what they gain>
```

Discipline rules for evidence:

- **No hallucinated paths or line numbers.** Every cited `file:line`
  must be one you actually read. Quote the code you're citing.
- **Show the caller.** When a bug depends on a caller, cite the calling
  code by `file:line` too.
- **Threat model for crypto.** State what the attacker controls, what
  they do not, what the bug lets them achieve. "Severity: High" with no
  threat model is not a finding — it is opinion.
- **Quote, don't paraphrase.** Findings must include the source lines
  verbatim so the maintainer can grep them.

## Pre-stated NOT bugs (do not re-report)

These are documented, deliberate design decisions. Re-flagging any of
them as bugs lowers the signal of the audit. Skip them unless you can
show the implementation deviates from the documented design.

1. **`PqJwtValidator.Validate` is synchronous.** `IPqJwtKeyRing.Resolve`,
   `IPqJwtReplayCache.TryRegister`, and the bearer-handler integration
   all flow through a sync interface intentionally. Making them async is
   a `2.0`-tier change. Flag a *measured* sync-over-async hotspot if you
   have one; do not flag the design.
2. **`HttpPqJwtKeyRing.Resolve` is a pure cache lookup** (since
   `1.0.0-preview.9`). The cache is populated by an `IHostedService`
   background loop, not by Resolve. If the cache is empty at runtime
   that's a consumer-side hosted-service registration bug, not a library
   bug.
3. **`InMemoryReplayCache` is single-process by design.** It does not
   coordinate across machines or survive restart;
   `KNOWN-GAPS.md` is explicit. Distributed deployments implement
   `IPqJwtReplayCache` over Redis (see
   `samples/ProductionDeploymentDemo/OrdersApi/RedisReplayCache.cs`).
   Flag a *correctness* bug in the single-process path; do not flag the
   single-process behaviour itself.
4. **`samples/DistributedReplayCache/DistributedCacheReplayCache` is a
   documented-known unsafe sample.** It ships an explicit "SCALE
   WARNING" prologue stating `IDistributedCache` has no atomic
   set-if-absent and that this class is for low-traffic / non-production
   use only. The intended production primitive is `RedisReplayCache` in
   the same file. Flag only if this class is being silently used as a
   production primitive elsewhere.
5. **No constant-time guarantees beyond BCL + BouncyCastle.**
   `KNOWN-GAPS.md` is explicit. Flag a constant-time issue only with a
   measurable timing oracle inside *library code we own*, not in the
   underlying primitives.
6. **No multi-recipient JWE, no `zip:DEF` compression, no algorithm
   agility, no composite signatures.** All deliberate `1.0` scope
   decisions; see `KNOWN-GAPS.md` and `docs/adr/0001-algorithm-agility.md`.
7. **`samples/WebApiDemo` defaults to an ephemeral signing key with a
   loud warning.** This is intentional. Same for any sample that
   generates keys at startup.
8. **The validator throws fail-closed by design.** Every validation
   failure raises a typed `PqJwtValidationException`. Wrapping these in
   a try/catch and returning a result is not the contract.

## Pre-stated existing assurance layers (don't duplicate)

Before flagging "this isn't tested", check that none of these already
cover it:

| Layer | Location |
|---|---|
| Unit, KAT, invariant, boundary, red-team tests | `tests/PostQuantum.Jwt.Tests/` |
| Roslyn analyzers (PQJWT001, PQJWT002) | `src/Analyzers/` and their tests in `tests/PostQuantum.Jwt.Analyzers.Tests/` |
| Tier-1 FsCheck adversarial fuzz | `PqJwtFuzzTests.cs` |
| Tier-2 coverage-guided fuzz (SharpFuzz + libFuzzer) | `fuzz/PostQuantum.Jwt.Fuzz/` |
| Mutation testing (Stryker.NET) | `stryker-config.json` |
| TLA+ formal model (TLC-checked) | `docs/formal/PqJwtValidator.tla` |
| Static analysis | `.github/workflows/codeql.yml` |
| Differential JOSE interop | `JoseInteropTests.cs` |
| Constant-time verify probe (opt-in) | `ConstantTimeVerifyTests.cs` |
| Validator-specific audit checklist | `docs/PQ-JWT-AUDIT-PROMPT.md` |
| External outreach + responses | `docs/AUDIT-OUTREACH.md` |
| Reviewer-facing test pyramid | `docs/TESTING.md` |

A genuine gap in these layers IS a finding. "This isn't tested" without
checking the above is not.

## What to check explicitly

### General

Logic errors, null / none dereferences, boundary conditions
(empty / zero / max / overflow / off-by-one), resource leaks, concurrency
(races, non-atomic check-then-act, shared mutable state, native-handle
disposal during in-flight verify), error handling (swallowed exceptions,
missing rollback), type / coercion mistakes, dead / unreachable code,
code that contradicts its own docstring / comment / signature.

### JWT-specific correctness

- **`alg` confusion / downgrade** — is `alg` read from the token header
  and trusted to select the verification path? Is `alg: none` ever
  accepted? Can a PQ alg be swapped for a classical one?
- **Algorithm pinning** — does verification pin the expected `alg`,
  `enc`, `cty`, `typ` values, or accept whatever the token claims?
- **Signature-before-claims ordering** — is the signature verification
  result actually checked on every path? Any branch that parses or
  trusts claims before verifying the signature?
- **Claim validation** — `exp`, `nbf`, `iat` with clock skew; `aud`,
  `iss`, `sub` enforced when expected; missing-claim vs. invalid-claim
  handling.
- **Base64url** — unpadded canonical encoding, rejection of non-canonical
  variants (embedded whitespace, slack bits in the final character),
  rejection of malformed lengths (including `length % 4 == 1`).
- **JSON parsing** — duplicate keys, type confusion (string vs. array
  `aud`), integer vs. float timestamps, depth / size limits, oversized
  input.
- **Key handling** — wrong key type accepted for an `alg`; public used
  where private is expected (or vice versa); `kid` trust and injection;
  `jku` / `jwk` / `x5u` / `x5c` ignored for key selection.

### Post-quantum / crypto correctness

- **Real primitives vs. simulation** — signing / verification calls the
  actual `MLDsa` / `MLKem` / `XWing` implementation, not a stub.
- **Hybrid confidentiality construction** — X-Wing is hybrid for
  *encryption* (`MLKem.Encapsulate` + X25519, combined with SHA3-256);
  *signatures* are pure ML-DSA-65. Verify both halves of the combiner
  are required for the encrypted path. Verify the combiner order and
  length-prefixing match `draft-connolly-cfrg-xwing-kem`.
- **Parameter-set mismatch** — signer and verifier on the same parameter
  set (ML-DSA-65 throughout this codebase); encoded in header and
  validated at verify time.
- **Non-constant-time comparison** — any `==` / `.Equals` /
  `memcmp`-style compare on signatures, MACs, or secrets. Require
  `CryptographicOperations.FixedTimeEquals` for those.
- **Randomness** — `RandomNumberGenerator` (CSPRNG), not `Random` /
  `Math.random`, for any nonce / salt / key material; correct nonce
  length (12 bytes for AES-GCM); no nonce reuse.
- **Signature / key encoding** — byte-length checks before parse;
  rejection of truncated or oversized blobs; no silent truncation; AEAD
  tag length pinned to profile (16 bytes here), never read from the
  token.
- **Determinism assumptions** — code assuming deterministic signatures
  where the scheme is randomized (ML-DSA-65 is randomized by default in
  the BCL).
- **Memory hygiene** — secret material zeroed via
  `CryptographicOperations.ZeroMemory` and disposed deterministically;
  no plaintext or key handle leaking to a finalizer-only lifecycle on
  a hot path.
- **Native-handle concurrency** — `MLDsa` / `MLKem` / `XWingPrivateKey`
  instances disposed only after no concurrent reader can be mid-verify
  on the native pointer (e.g. via the deferred-disposal quarantine
  pattern used in this repo).

### VS Code extension specifics

- **CSP correctness** in any webview; `randomBytes(16)`-derived nonces
  applied to every `<script>` tag.
- **`openExternal` / URI handling** restricted to a host-computed
  allowlist; no scheme or path traversal from webview messages.
- **No secrets, keys, or tokens** written to logs, output channels, or
  `globalState`; the `secrets` API is used for sensitive values.
- **Message-passing** between webview and extension host validates
  origin and message shape; no `postMessage` data evaluated or
  DOM-injected unsanitised.
- **HTML escaping** for any token-derived text rendered in the
  inspector webview.

## Severity rubric (must be threat-modelled)

| Severity | Definition |
|---|---|
| **Critical** | A remote attacker with no prior access can forge a token the validator accepts, bypass replay defense in a deployment that documents replay protection as enabled, or recover key material. |
| **High** | A remote attacker can cause unauthenticated denial of service, can be silently accepted under attacker-influenced conditions (case variants, malformed input), or can race the verifier into an inconsistent state under realistic load. |
| **Medium** | An interop / reliability bug an attacker cannot trigger directly but that breaks standards-compliant clients, or that causes graceful behaviour to become ungraceful under non-adversarial load. |
| **Low** | A correctness or code-quality bug with no security impact — a wrong default a careful operator overrides, a wasteful pattern, a misleading comment. |
| **Info** | A note worth recording but not a bug — dead code, possible future refactor, design observation. |

If you cannot articulate the threat model, the finding is not Critical
or High. Default to Low / Info unless the model is concrete.

## Output contract

Produce **one Markdown file**, with this exact top-level structure (the
maintainer parses it; deviations slow the response loop):

````markdown
# <reviewer-name>: PostQuantum.Jwt — Whole-Repo Bug Audit

**Auditor:** <name-or-model-id>
**Date:** YYYY-MM-DD
**Scope:** Every source file under `src/**/*.cs`, `samples/**/*.cs`,
`tools/vscode/src/**/*.ts` (the three globs in the audit prompt).
**Method:** File-by-file read. No sampling. All findings proven from
code actually present.

---

## File inventory

Three tables — one per scope area. Every file you read appears here
with its finding count. Files with zero findings stay in the inventory
so the maintainer can see they were covered.

### Core library (`src/`)

| File | Bugs |
|---|---:|
| `src/PostQuantum.Jwt/PqJwtValidator.cs` | 0 |
| `…` | `…` |

### Samples (`samples/`)

| File | Bugs |
|---|---:|
| `…` | `…` |

### VS Code extension (`tools/vscode/src/`)

| File | Bugs |
|---|---:|
| `…` | `…` |

---

## Summary

| # | File | Severity | Category | One-line description |
|---|---|---|---|---|
| 1 | `samples/…/X.cs` | High | Concurrency | … |
| 2 | `src/…/Y.cs` | Medium | Interop | … |

---

## Findings

One `### BUG-N · Severity · Category` heading per finding, in Summary
order. Each finding contains the **Evidence block** quoted from the
file, followed by a **Fix** paragraph proposing the smallest correct
change in prose. Do NOT apply the fix to the code.

### BUG-1 · High · Concurrency

**File:** `samples/.../X.cs`
**Lines:** L–L  (the exact range read)

```csharp
// BUG: …
// PROOF: …
// TRIGGER: …
// SEVERITY: …
<verbatim source lines from the file>
```

**Fix:** <smallest correct change, in prose; no patch>.

---

## Previously-found bugs

If the repo root contains earlier reviewer files with a "Resolution"
section (e.g. `claudbugsfound.md`, `new668.md`, etc.), verify which of
the previously-flagged bugs are still present in current source.

- **FIXED** items cite the Resolution commit by SHA.
- **REMAINS** items cite the current file:line where the bug still
  exists.

Do NOT include speculative or unproven re-flags.

---

## Coverage statement

One paragraph stating which files were fully read and which were
skipped (must match the "Out of scope" list in the prompt). End with
the exact sentence:

> Entire requested repository scope has been covered. <N> proven
> bug(s) reported.

---

## Suspected, unproven (optional, max 3 items)

Up to three items where you saw something that *might* be a bug but
could not prove from current code. State exactly what additional
evidence would be needed — a test run, a specific input, a
clarification from the maintainer. Pad this section and the whole
audit loses value.
````

## Rules

1. **No fixes.** Audit only. Propose the smallest correct change in
   prose; do not patch the code.
2. **No padding.** Empty sections beat fabricated findings.
3. **No speculation in findings.** Move uncertain items to "Suspected,
   unproven" or omit them.
4. **No re-flagging the Pre-stated NOT bugs** unless you demonstrate the
   implementation deviates from the documented design.
5. **Cite file:line for every claim.** Hallucinated paths or line
   numbers poison the entire audit; the maintainer discards the report
   after the first wrong cite. If you couldn't open the file, say so.
6. **Severity must be threat-modelled.** Critical / High require an
   articulated attacker model.
7. **One file, one delivery.** Don't deliver findings piecemeal.

## How the maintainer uses your output

The audit file is committed to the repo root verbatim. When a bug is
addressed, a "Resolution" section is appended to your file citing the
fix commit. Future audits read your "Previously-found bugs" section to
know what's already been chased. Keep that chain in mind when writing:
be specific, be cite-able, be diff-able.

---

*To God be the glory — 1 Corinthians 10:31.*
