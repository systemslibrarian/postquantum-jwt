# Formal model — `PqJwtValidator`

A small [TLA+](https://lamport.azurewebsites.net/tla/tla.html) state-machine model
of the token validator, model-checked with TLC. It exists to prove the
**protocol-orchestration invariants** — the class of flaw JWT libraries get wrong
far more often than the underlying cryptography (skipped checks, accept-without-
verify, profile downgrade, header-driven algorithm selection).

## What it proves

TLC exhaustively checks every reachable state and confirms:

| Invariant | Meaning | Test counterpart |
|---|---|---|
| `NoAcceptWithoutVerify` | No path reaches `accept` without a verified ML-DSA signature. | `Signature_is_verified_before_claims_…` |
| `AcceptIsSound` | Acceptance implies **every** gate passed — size, segments, alg, kid, signature, claims, replay, and (for encrypted tokens) decrypt-to-a-signed-inner. | `SecurityInvariantsTests` (all) |
| `Termination` | Validation always ends in a definite `accept`/`reject` — fail-closed, no stuck/degraded state. | `PqJwtFuzzTests` (fail-closed totality) |

Last run: **4,706 distinct states, no error found** (TLC 2.19).

## Honest scope and limitations

- **This models the control flow, not the cryptography.** ML-DSA verification,
  X-Wing decapsulation, AES-GCM, Base64Url, and JSON are the Trusted Computing
  Base; the model treats their outcomes as opaque booleans (`sigValid`,
  `decryptOk`, …) and has TLC enumerate all combinations. It does **not** prove
  any primitive correct — those are the BCL's / BouncyCastle's job (and are
  being formally verified upstream; see `KNOWN-GAPS.md`).
- **It proves the *model*, not the C#.** The model mirrors
  `src/PostQuantum.Jwt/PqJwtValidator.cs` and `docs/SPEC.md` by hand. What keeps
  the model and the code from drifting apart is `SecurityInvariantsTests` —
  each TLA+ invariant has a runtime test counterpart (table above). Treat the
  two as a pair: the model says "the design is sound for all input
  combinations," the tests say "the code implements that design."
- **It is not run in CI.** It needs a Java + TLA+ toolchain, which the build
  deliberately does not depend on. It is a developer-run artifact; re-run it
  when the validation pipeline changes.

This is intentionally a *narrow, high-value* formalization, not a program to
verify the whole library — see the discussion in the project history for why a
full proof effort would be disproportionate for a thin orchestration layer over
trusted primitives.

## Running it

```bash
# One-time: fetch the TLA+ tools (TLC).
curl -sSL -o tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar

# Model-check (reads PqJwtValidator.cfg by convention).
java -cp tla2tools.jar tlc2.TLC PqJwtValidator.tla
```

Expect `Model checking completed. No error has been found.`

---

*To God be the glory — 1 Corinthians 10:31.*
