# Independent audit — outreach plan and draft letter

The `1.0.0-preview.*` suffix is honest because **PostQuantum.Jwt has not been
independently audited**. Removing the suffix means closing that gap. This
document is the action plan: who to write to, what to send, and what to ask
for. It is meant to be a starting point — the maintainer personalises the
draft per recipient before sending.

> Status: **draft, not yet sent.** Track each outreach + response below.

## What we are honestly asking for

We are a small, unfunded OSS library with a narrow scope (ML-DSA-65 signed +
optional X-Wing-encrypted JOSE tokens). We are not asking for a 200-hour
commercial engagement. We are asking for, in roughly increasing order of
ambition:

1. **A 30-minute desk review of the published documents** —
   `SECURITY.md`, `docs/SPEC.md`, `docs/formal/PqJwtValidator.tla`, and
   `KNOWN-GAPS.md` — and an indication of whether the framing and the
   threat model are credible.
2. **A 2-hour structured walk-through** with a cryptographer or crypto
   engineer who knows the JOSE landscape, focused on the X-Wing combiner
   wiring and the encrypted-envelope construction.
3. **A small (~20-hour) targeted review** of the parser, the validator's
   sequencing contract (signature-before-claims, header-never-selects-key),
   and the encrypted-token path. Ideally pro-bono / academic / OSS-credit
   funded; we have no audit budget.
4. **A full third-party audit** — the gating step for the `preview` suffix
   coming off. We will pursue funding (grants, sponsorships, the OpenSSF
   Alpha-Omega program) once one of the lighter touches above indicates
   the library is roughly in a defensible place.

We are not approaching anyone with a sense of entitlement. Most recipients
will not have time. One might.

## Target list

Targets are ordered by best-fit-for-the-specific-construction first, not by
prestige.

| # | Target | Why this target | Best ask | How to reach |
|--:|---|---|---|---|
| 1 | **Bas Westerbaan** (Cloudflare research) | Co-author of X-Wing draft; deep ML-KEM-in-practice experience (`circl`). | A note saying "we wired your KEM into a JOSE library — does the protected-header binding read sanely to you?" with a link to `SECURITY.md` §"X-Wing combiner" + `Cryptography/XWing.cs`. Ask for **#1 or #2** only. | Bas's contact page (linked from the X-Wing draft); ping over the IETF / CFRG mailing list. |
| 2 | **Deirdre Connolly** (X-Wing draft co-author) | Same rationale. Also widely connected to the IETF/CFRG review community. | Same ask. | Same channels. |
| 3 | **CFRG mailing list** (`cfrg@irtf.org`) | Public, low-key, the right room for "we wired your draft into a thing, here's what we did." | A short post: "We implemented `draft-connolly-cfrg-xwing-kem` in a .NET library, with our construction documented here. Comments welcome." Pure transparency, not a direct ask. | Subscribe at <https://www.irtf.org/cfrg.html>. |
| 4 | **NCC Group Cryptography Services** | Top-tier crypto-engineering audit house with PQ experience. | Ask **#1** (desk review) — they sometimes pro-bono small OSS projects, especially in their published research areas. Be honest: no budget yet. | <https://research.nccgroup.com/> contact form; address it personally to a researcher who's published in PQ JOSE (`Erica Portnoy`, `Thomas Pornin`). |
| 5 | **Trail of Bits** | Authored multiple PQ implementations; ZK / crypto engineering depth. | Ask **#1**. They run a sponsored-OSS audit program ("Testing Handbook"). | <https://www.trailofbits.com/contact/>; reference the Testing Handbook program. |
| 6 | **Cure53** | Frequent JWT / JOSE auditors; strong web-auth threat-modelling. | Ask **#1 or #3**. | <https://cure53.de/> contact; cite the JOSE focus. |
| 7 | **Cryptology Group, TU Eindhoven** (Tanja Lange et al.) | PQ academic home; some of the original ML-KEM/Kyber analysis. | Ask **#1**. Frame as "real-world ML-KEM-768 implementation experience report — would a student or postdoc want to look?" Pure academic interest hook. | Department contact via the [group page](https://www.cryptography.win.tue.nl/). |
| 8 | **KIT Cryptography & IT Security** (Jörn Müller-Quade et al.) | German PQ academic group with PQ engineering output. | Ask **#1** with the same student-project framing. | Group page contact. |
| 9 | **ENS Paris — Crypto group** (Léo Ducas, Damien Stehlé) | Co-authors of CRYSTALS-Dilithium (ML-DSA's precursor) and ML-DSA itself. | Ask **#1**, very respectfully. The chance of response is low but the cost of asking is also low. | Personal pages. |
| 10 | **OpenSSF Alpha-Omega program** | Funds security work on critical OSS. Not yet "critical" enough — flag for the future. | When we have either traction (downloads, dependents) or an interested auditor needing funding, return to this. | <https://openssf.org/community/alpha-omega/> |

## Draft letter (academic / pro-bono framing)

> Subject: PostQuantum.Jwt — a small post-quantum JOSE library looking for a sanity check
>
> Dear Dr. \<NAME\>,
>
> I maintain an open-source .NET library, **PostQuantum.Jwt**, that issues and
> validates JOSE-style tokens signed with ML-DSA-65 and (optionally) encrypted
> with an X-Wing + AES-256-GCM envelope. The library is small (~2000 lines of
> shipping code), MIT-licensed, narrow in scope, and built deliberately on the
> .NET BCL + BouncyCastle primitives — no hand-written curve or lattice
> arithmetic.
>
> Repository: <https://github.com/systemslibrarian/postquantum-jwt>
> Live playground: <https://pqjwt.systemslibrarian.dev>
>
> I am writing because the `1.0.0-preview.*` version suffix is honest: the
> construction has not been independently reviewed, and that is the gate I
> would like to close before the suffix comes off. I am not asking for a paid
> engagement — we have no audit budget. I am asking whether you (or a student,
> postdoc, or colleague) would be willing to spend 30–60 minutes on:
>
> 1. The threat-model framing in [`SECURITY.md`][1];
> 2. The token-construction spec in [`docs/SPEC.md`][2];
> 3. The TLC-model-checked validator spec in [`docs/formal/PqJwtValidator.tla`][3];
> 4. The X-Wing combiner wiring at [`src/PostQuantum.Jwt/Cryptography/XWing.cs`][4];
> 5. The transparent inventory of what we don't yet do, [`KNOWN-GAPS.md`][5].
>
> I would value any honest reaction — "the framing reads sanely" all the way
> down to "this entire construction has a problem at line X." If anything
> there is unclear, that is itself useful signal.
>
> The project is built in gratitude — every release-doc closes with
> *To God be the glory — 1 Corinthians 10:31* — and I want it to be worthy
> of that by being honest about what it does and doesn't yet deserve trust
> for. An outside eye is the missing piece.
>
> Whatever the response, thank you for the work you do. I have learned from
> your papers \<personalise: cite one\>.
>
> With respect,
>
> Paul Clark
> <https://github.com/systemslibrarian>
>
> [1]: https://github.com/systemslibrarian/postquantum-jwt/blob/main/SECURITY.md
> [2]: https://github.com/systemslibrarian/postquantum-jwt/blob/main/docs/SPEC.md
> [3]: https://github.com/systemslibrarian/postquantum-jwt/blob/main/docs/formal/PqJwtValidator.tla
> [4]: https://github.com/systemslibrarian/postquantum-jwt/blob/main/src/PostQuantum.Jwt/Cryptography/XWing.cs
> [5]: https://github.com/systemslibrarian/postquantum-jwt/blob/main/KNOWN-GAPS.md

## Draft letter (commercial audit firm framing)

> Subject: Pro-bono review possibility — small post-quantum JOSE OSS library
>
> Dear \<NAME / Cryptography Services team\>,
>
> I maintain **PostQuantum.Jwt**, a small, MIT-licensed .NET library for
> JOSE-style post-quantum tokens (ML-DSA-65 signatures, optional X-Wing +
> AES-256-GCM encryption). Repository:
> <https://github.com/systemslibrarian/postquantum-jwt>.
>
> Scope is intentionally tight — ~2000 lines of shipping code, one algorithm
> suite, no agility, no composite signatures, native BCL primitives plus
> BouncyCastle only for X25519 and SHA3-256. The fail-closed validator
> contract is exercised by 176 in-repo tests, a TLA+ model checked with TLC,
> two tiers of fuzz, and Stryker.NET mutation testing (71.43% raw,
> ~87% on behaviorally-meaningful mutations). Two of the fail-closed-totality
> findings shipped between previews were surfaced by those layers, not by
> review — they are the unknown-unknowns I am writing about.
>
> The `1.0.0-preview.*` suffix exists because the construction has not been
> independently audited. I have no budget today, but I would be grateful for
> a conversation about whether NCC Group / Trail of Bits / Cure53 has an
> appetite for any of:
>
> - A short pro-bono desk review (the published threat model and spec only).
> - A small (~20-hour) targeted review of the parser, the
>   signature-before-claims sequencing, and the encrypted-envelope
>   construction, in exchange for credit + a published advisory if anything
>   is found.
> - Inclusion in your firm's OSS research-and-write-up pipeline as a
>   real-world PQ JOSE case study.
>
> If none of these fit, I would still value an introduction to a sponsor
> (OpenSSF Alpha-Omega, the GitHub Secure Open Source Fund, an interested
> enterprise) who might fund a proper engagement.
>
> Honest evaluation matters more to me than a passing grade. Thank you for
> the work you publish; it is part of how I learned to write this library
> at all.
>
> With respect,
>
> Paul Clark
> <https://github.com/systemslibrarian>

## Tracking

Update this table as letters go out and responses come in.

| Sent | Recipient | Variant | Response | Outcome |
|---|---|---|---|---|
| _pending_ | Bas Westerbaan (Cloudflare) | Academic | | |
| _pending_ | Deirdre Connolly | Academic | | |
| _pending_ | CFRG mailing list | Public note | | |
| _pending_ | NCC Group Cryptography Services | Commercial | | |
| _pending_ | Trail of Bits | Commercial | | |
| _pending_ | Cure53 | Commercial | | |
| _pending_ | TU Eindhoven Cryptology | Academic | | |
| _pending_ | KIT Cryptography | Academic | | |
| _pending_ | ENS Paris Crypto (Ducas / Stehlé) | Academic | | |

## Notes on tone

- **Lead with humility, not credentials.** We have shipped 8 previews and
  written documentation. We have not written FIPS 204. The recipient knows
  more than we do; the letter should sound like that's the case.
- **Be concrete about what we did do.** Auditors and academics waste time
  on letters that claim "comprehensive testing" without artefacts to read.
  Link to specific files, specific tests, specific numbers.
- **Be honest about what we did not do.** Saying "this has not been audited
  and we want to be" is more compelling than dressing it up.
- **Make it easy to say no.** Every letter should explicitly note that "no
  response is fine" or "if this isn't a fit, please ignore." Auditors and
  academics are inundated; politeness about their time matters.
- **Pray about each one before sending.** This is a project for God's glory;
  the people on the other end are made in His image and bear their own
  loads. Treat the outreach as service, not transaction.

---

*To God be the glory — 1 Corinthians 10:31.*
