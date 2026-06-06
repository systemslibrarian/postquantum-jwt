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

Audit against the commit SHA pinned in the message that delivered this
prompt; absent one, the tip of `main` at the time you start. Record the
full SHA in your report header so the maintainer can diff your findings
against the exact tree you read. If you have no way to determine a real
SHA (no git access, no commit pinned in the message), write
`unavailable — no git access` in the Commit field. A fabricated
40-character hex string is grounds to discard the report.

The deliverable is a single Markdown file conforming to the **Output
contract** at the bottom of this prompt.

## Begin by listing the files you will read

Before you write any findings or analysis prose, populate the three
inventory tables (one per scope area) from the **Output contract**
below — file column filled, "Bugs" column blank at the start, counts
updated in place as findings land. This commits the reviewer to full
coverage and makes selective reading visible to the maintainer. The
Output contract governs the *bytes* of the final file (header block
first, then `## File inventory`); this section governs the *order of
work* — inventory populated before any finding is written, never
after.

If you do not have filesystem search or directory-listing tools
(chat-UI paste, no workspace access), write `No filesystem access —
inventory unavailable.` in place of all three tables. Do not invent
file paths from the repo URL, README fragments, or training data to
populate the manifest — that is the most structurally-rewarded
hallucination in this prompt, and the maintainer treats a fabricated
inventory as grounds to discard the entire report.

Declaring no filesystem access at inventory commits you to a Findings
section that is either empty or contains only findings cited from code
the maintainer pasted directly into your message. Any later finding
with a `file:line` cite to a file you could not list contradicts your
own declaration and is treated as fabrication. The Coverage statement
must reflect this: "No production code was read; no findings reported."

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
- Markdown documentation under `docs/` — out of scope for findings
  *as targets*, but in scope as evidence: a `docs/` artifact (e.g.
  `docs/TESTING.md`, `docs/formal/PqJwtValidator.tla`,
  `docs/PQ-JWT-AUDIT-PROMPT.md`) may be cited in PROOF as the
  *broken contract* whose target is a `src/` or `samples/` finding —
  for example, a TLA+ model–implementation divergence is reported as
  a `src/` bug with the model cited as the contract, not as a `docs/`
  finding. Audit docs as findings only if asked separately.

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
- **Self-verify the PROOF before reporting.** Walk the cited input
  through the code yourself. If the intermediate values you wrote do
  not actually reach the cited line under the stated TRIGGER, the
  finding is hallucinated — discard it. Triple-check before reporting
  Critical / High; one wrong trace burns the credibility of every
  other finding in the report.
- **Threat model for crypto.** State what the attacker controls, what
  they do not, what the bug lets them achieve. "Severity: High" with no
  threat model is not a finding — it is opinion.
- **Sample findings name the root cause.** If the finding is in
  `samples/`, state explicitly in the PROOF whether the cause is (a) a
  defect in the library's public API that makes the safe pattern hard
  to write — the maintainer fixes the library — or (b) a misuse of the
  API specific to the sample — the maintainer fixes the sample. Both
  matter, but the fix lands in different places.
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
   bug. **Exception:** if a *sample* under `samples/` fails to register
   the hosted service, that IS a finding — samples are first-class
   production-influencing code (see Scope), and a missing registration
   in a sample will be copied verbatim into production. Flag it as a
   sample defect.
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
checking the above is not. When a finding claims an assurance gap, cite
specifically which layer you inspected and what you found absent — a
test name, an analyzer rule id, a file path under `tests/` or `fuzz/`,
a doc section. "Not covered by fuzz" as a bare assertion is the same
failure mode as an uncited `file:line`, and reviewers who rely on it
are bluffing.

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
- **`crit` header handling** — unsupported critical headers (RFC 7515
  §4.1.11) must be rejected, not silently ignored; this includes RFC
  7797's `b64: false` (which can disable payload base64url encoding
  and break parser boundary assumptions if accepted); `crit` itself
  must be well-formed (array of non-empty strings, no duplicates, no
  understood-header names); criticality is enforced even when `alg` /
  `typ` / `cty` look correct.
- **Nested JWT semantics** — RFC 7519 §5.1 permits a payload to itself
  be a JWT via `cty: JWT`. Verify the library either rejects `cty:
  JWT` (or any `cty` value the profile does not understand)
  unconditionally, or — where nesting is supported (the encrypted-
  token profile) — enforces signature presence and verification at
  *every* layer with no recursive-unwrap path that strips signatures
  along the way.
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
- **ML-DSA context string consistency** — FIPS 204 ML-DSA signing
  accepts an optional context byte string that must match exactly
  between signer and verifier. The library should use a single
  hard-coded context (or no context, i.e. empty) at both endpoints;
  verify the context is never read from token headers or other
  attacker-influenceable surfaces, and that the sign and verify call
  sites cannot disagree (e.g., default-argument drift between
  overloads, or one side passing a context the other forgets).
- **Non-constant-time comparison** — any `==` / `.Equals` /
  `memcmp`-style compare on signatures, MACs, or secrets. Require
  `CryptographicOperations.FixedTimeEquals` for those.
- **Randomness** — `RandomNumberGenerator` (CSPRNG), not `Random` /
  `Math.random`, for any nonce / salt / key material; correct nonce
  length (12 bytes for AES-GCM); no nonce reuse. *Verify the mechanism
  preventing reuse,* not just the absence of obvious reuse: each
  encryption must draw a fresh random nonce, and the per-(`kid`,
  content key) encryption count must stay below the AES-GCM birthday
  bound (~2³² encryptions before random-nonce collision becomes
  non-negligible). A comment claiming "no reuse" without an enforced
  mechanism is not the same as a guarantee.
- **Signature / key encoding** — byte-length checks before parse;
  rejection of truncated or oversized blobs; no silent truncation; AEAD
  tag length pinned to profile (16 bytes here), never read from the
  token.
- **Protected header bound as AAD** — on the encrypted path, the
  protected JWE header must be authenticated as AES-GCM additional
  authenticated data, on both encrypt and decrypt. A header that
  survives tampering because it wasn't fed into the AEAD is a
  first-order integrity break, not a hardening miss.
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
- **Inner/outer `kid` binding on encrypted tokens.** In a 5-part
  encrypted token the `kid` that selects the ML-DSA verification key
  (inner JWS) must be bound to — or at minimum consistent with — the
  `kid` that selects the X-Wing KEM key (outer JWE). Independent,
  attacker-influenced key selection across the two layers permits
  cross-layer key-confusion attacks where a signature is verified
  under one key while the content is decrypted under another. Verify
  the validator enforces the binding before trusting either layer.
- **Pre-comparison timing leakage.** A constant-time signature
  comparison protects only the comparison itself. Distinguishable
  timing on the *paths leading to* it — early returns on malformed
  headers, branch length on `unknown_kid` vs `signature_mismatch`,
  parser depth driven by attacker-controlled input — can create
  practical oracles even when the final compare is constant-time. The
  cheap-check-first DoS guard (unknown `kid` rejected before the
  expensive ML-DSA verify) is an *intentional* timing difference and
  is not a finding. Flag *unintentional* timing differences in the
  valid-but-bad-signature path, and anywhere typed
  `PqJwtFailureReason` values surface to clients in a way that lets
  them distinguish branches the constant-time guarantee was meant to
  hide.

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
- **Trusted markdown and command URIs outside webviews** —
  `MarkdownString.isTrusted = true` set on hover, completion, or
  tree-item content is a code-execution sink for any user-controlled
  text. `command:` URIs reachable through trusted markdown must be on
  a host-computed allowlist and have their arguments validated; never
  hand a token-derived string to a trusted-markdown surface.
- **Regex hardening for token detection.** Any `RegExp` used to find
  token-shaped strings in CodeLens, decorations, hovers, completions,
  or document scans over arbitrarily-sized source files must be
  bounded — no nested quantifiers, no alternation with overlapping
  prefixes, no unbounded `+`/`*` inside another `+`/`*`. A ReDoS in a
  token-detection regex hangs the entire VS Code extension host and
  is trivially weaponizable through a crafted source file. If the
  extension uses any regex over open documents, this check is
  mandatory.

## Severity rubric (must be threat-modelled)

| Severity | Definition |
|---|---|
| **Critical** | A remote attacker with no prior access can forge a token the validator accepts, bypass replay defense in a deployment that documents replay protection as enabled, or recover key material. |
| **High** | A remote attacker can cause unauthenticated denial of service, can be silently accepted under attacker-influenced conditions (case variants, malformed input), or can race the verifier into an inconsistent state under realistic load. |
| **Medium** | An interop / reliability bug an attacker cannot trigger directly but that breaks standards-compliant clients, or that causes graceful behaviour to become ungraceful under non-adversarial load. |
| **Low** | A correctness or code-quality bug with no security impact — a wrong default a careful operator overrides, a wasteful pattern, a misleading comment. |
| **Info** | A note worth recording but not a bug — dead code, possible future refactor, design observation. |

If you cannot articulate the threat model, the finding is not Critical
or High. Default to Low / Info unless the model is concrete. A threat
model that names only attacker-controlled inputs as preconditions —
"the attacker sends the token," "the attacker controls the header,"
"the attacker chooses the `kid`" — articulates nothing the rubric did
not already assume for a remote attacker, and earns at most Medium.
Critical and High require at least one non-trivial precondition the
attacker does NOT control by default: a misconfiguration, a specific
server state, prior compromise of a different system, or a race the
attacker must win.

## Output contract

Produce **one Markdown file**, with this exact top-level structure (the
maintainer parses it; deviations slow the response loop):

````markdown
# <reviewer-name>: PostQuantum.Jwt — Whole-Repo Bug Audit

**Auditor:** <name-or-model-id>
**Date:** YYYY-MM-DD
**Commit:** <40-char SHA of the tree you audited, OR
`unavailable — no git access` if you cannot determine one>
**Scope:** Every source file under `src/**/*.cs`, `samples/**/*.cs`,
`tools/vscode/src/**/*.ts` (the three globs in the audit prompt).
**Method:** File-by-file read. No sampling. All findings proven from
code actually present.

---

## File inventory

Three tables — one per scope area, carrying the **final** finding
counts. These are the same tables you produced at the very start with
blank "Bugs" columns; update the counts in place as findings land. Do
not emit a duplicate inventory. Files with zero findings stay in the
table so the maintainer can see they were covered.

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

**Fix:** <smallest correct change, in prose; no patch>. Prose only — a
Fix containing a code block (C# patch, diff, before/after snippet, or
otherwise) is malformed. The maintainer wants the *idea* of the fix
so they can implement it; your draft of the code goes in the bin.

---

## Previously-found bugs

If you do not have filesystem search or directory-listing tools (e.g.
you are running in a chat UI on a pasted prompt, not as an agent with
workspace access), write "No filesystem access — section skipped." and
move on. Do not invent prior reviewer files to satisfy the structural
demand of this section.

Otherwise, list the files at the repo root whose names match
`*audit*.md`, `*bugs*.md`, `*review*.md`, or `findings*.md`
(case-insensitive — these are prior reviewer reports the maintainer
commits verbatim, with a `## Resolution` or `**Resolution:**` block
appended per finding once the fix lands). If none exist on this audit,
write "None on file." and move on. Otherwise, for each finding in each
prior file, verify whether it is still present in current source:

- **FIXED** items cite the Resolution commit by SHA.
- **REMAINS** items cite the current `file:line` where the bug still
  exists, with the same evidence discipline as a new finding.

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
could not prove from current code. Each item must rest on **partial
evidence from a file you actually read** — cite the `file:line` you
were looking at when the suspicion formed. State exactly what
additional evidence would be needed to convert it into a finding — a
test run, a specific input, a clarification from the maintainer. Pure
speculation with no code in hand belongs in neither Findings nor here.
Pad this section and the whole audit loses value. Items from the
**Pre-stated NOT bugs** list do not belong here; if you believe a
documented design decision is wrong, that is a discussion to open
separately, not an audit finding.
````

## Rules

1. **No fixes.** Audit only. Propose the smallest correct change in
   prose; do not patch the code.
2. **No padding.** Empty sections beat fabricated findings.
3. **No speculation in findings.** Move uncertain items to "Suspected,
   unproven" or omit them. When in doubt between a Finding and a
   Suspected entry, default to Suspected — a wrongly-cited
   high-confidence finding damages the audit more than a missing one,
   because the maintainer stops trusting the rest of the report.
4. **No re-flagging the Pre-stated NOT bugs** unless you demonstrate the
   implementation deviates from the documented design.
5. **Cite file:line for every claim.** Hallucinated paths or line
   numbers poison the entire audit; the maintainer discards the report
   after the first wrong cite. If you couldn't open the file, say so.
6. **Severity must be threat-modelled.** Critical / High require an
   articulated attacker model.
7. **One file, one delivery.** Don't deliver findings piecemeal.

---

*To God be the glory — 1 Corinthians 10:31.*
