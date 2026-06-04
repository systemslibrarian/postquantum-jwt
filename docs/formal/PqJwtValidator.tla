---------------------------- MODULE PqJwtValidator ----------------------------
(***************************************************************************)
(* An abstract state-machine model of `PqJwtValidator.Validate`, used to   *)
(* MODEL-CHECK the protocol-orchestration invariants — the class of bug    *)
(* that JWT libraries get wrong far more often than the cryptography.      *)
(*                                                                         *)
(* What this models: the control flow / ordering of the validator, mirror- *)
(* ing `docs/SPEC.md` "Validation rules (fail-closed, in order)" and       *)
(* `src/PostQuantum.Jwt/PqJwtValidator.cs`.                                *)
(*                                                                         *)
(* What this does NOT model (deliberately): the cryptography. ML-DSA       *)
(* verification, X-Wing decapsulation, AES-GCM, Base64Url, and JSON are    *)
(* the Trusted Computing Base; their outcomes appear here only as opaque   *)
(* booleans (e.g. `sigValid`). TLC enumerates every combination of those   *)
(* outcomes, so the model covers all structural and cryptographic results  *)
(* at once. See README.md for the honest scope and limitations.           *)
(***************************************************************************)

VARIABLES
    pc,        \* phase / program counter (where validation currently is)
    outcome,   \* "pending" | "accept" | "reject"
    verified,  \* TRUE once the ML-DSA signature has actually been checked & passed
    tok        \* the token's abstract facts (fixed input; see TokenFacts)

vars == <<pc, outcome, verified, tok>>

Outcomes == {"pending", "accept", "reject"}

Phases ==
    {"size", "segments", "decrypt", "alg", "kid", "verify", "claims", "replay", "done"}

(* A token is a bundle of abstract facts. Each is chosen nondeterministically *)
(* in Init, so TLC explores all 2^8 * 3 = 768 combinations. For an encrypted  *)
(* token the alg/kid/sig/claim facts describe the INNER signed token.         *)
TokenFacts ==
    [ oversized   : BOOLEAN,                          \* exceeds the max accepted length
      shape       : {"signed", "encrypted", "malformed"}, \* 3-seg / 5-seg / other
      algOk       : BOOLEAN,                          \* header alg == ML-DSA-65
      kidKnown    : BOOLEAN,                          \* kid resolves to a trusted key
      sigValid    : BOOLEAN,                          \* ML-DSA verify succeeds (opaque)
      decryptOk   : BOOLEAN,                          \* X-Wing decap + GCM tag ok (opaque)
      innerSigned : BOOLEAN,                          \* decrypted content is a 3-seg signed token
      expOk       : BOOLEAN,                          \* exp/nbf within skew
      claimsOk    : BOOLEAN,                          \* iss/aud match
      jtiOk       : BOOLEAN ]                         \* replay check passes

TypeOK ==
    /\ pc \in Phases
    /\ outcome \in Outcomes
    /\ verified \in BOOLEAN
    /\ tok \in TokenFacts

Init ==
    /\ pc = "size"
    /\ outcome = "pending"
    /\ verified = FALSE
    /\ tok \in TokenFacts

(* SPEC step 1: oversized input is rejected before any parse/decode. *)
SizeStep ==
    /\ pc = "size"
    /\ \/ /\ tok.oversized
          /\ outcome' = "reject" /\ pc' = "done"
       \/ /\ ~tok.oversized
          /\ outcome' = "pending" /\ pc' = "segments"
    /\ UNCHANGED <<verified, tok>>

(* SPEC step 2: segment count. Signed -> alg checks; encrypted -> decrypt first. *)
SegmentsStep ==
    /\ pc = "segments"
    /\ \/ /\ tok.shape = "malformed"
          /\ outcome' = "reject" /\ pc' = "done"
       \/ /\ tok.shape = "signed"
          /\ outcome' = "pending" /\ pc' = "alg"
       \/ /\ tok.shape = "encrypted"
          /\ outcome' = "pending" /\ pc' = "decrypt"
    /\ UNCHANGED <<verified, tok>>

(* SPEC step 3 (encrypted only): decapsulate + AES-GCM, and the decrypted    *)
(* content MUST be a 3-segment signed token (no profile downgrade).          *)
DecryptStep ==
    /\ pc = "decrypt"
    /\ \/ /\ ~tok.decryptOk
          /\ outcome' = "reject" /\ pc' = "done"
       \/ /\ tok.decryptOk /\ ~tok.innerSigned
          /\ outcome' = "reject" /\ pc' = "done"
       \/ /\ tok.decryptOk /\ tok.innerSigned
          /\ outcome' = "pending" /\ pc' = "alg"
    /\ UNCHANGED <<verified, tok>>

(* SPEC step 4: alg MUST equal ML-DSA-65. The header never SELECTS a verify  *)
(* path — there is one suite — it is only a gate. (No alg-dependent branch    *)
(* exists anywhere in this model, mirroring the single hard-coded allowlist.) *)
AlgStep ==
    /\ pc = "alg"
    /\ \/ /\ ~tok.algOk
          /\ outcome' = "reject" /\ pc' = "done"
       \/ /\ tok.algOk
          /\ outcome' = "pending" /\ pc' = "kid"
    /\ UNCHANGED <<verified, tok>>

(* SPEC step 5: unknown kid rejected BEFORE the expensive verify. *)
KidStep ==
    /\ pc = "kid"
    /\ \/ /\ ~tok.kidKnown
          /\ outcome' = "reject" /\ pc' = "done"
       \/ /\ tok.kidKnown
          /\ outcome' = "pending" /\ pc' = "verify"
    /\ UNCHANGED <<verified, tok>>

(* SPEC step 6: verify the ML-DSA signature. This is the ONLY action that    *)
(* sets `verified`, and it is reachable only after the structural/kid gates. *)
VerifyStep ==
    /\ pc = "verify"
    /\ \/ /\ ~tok.sigValid
          /\ outcome' = "reject" /\ pc' = "done" /\ UNCHANGED verified
       \/ /\ tok.sigValid
          /\ verified' = TRUE /\ outcome' = "pending" /\ pc' = "claims"
    /\ UNCHANGED tok

(* SPEC step 7: claims (exp/nbf/iss/aud) — evaluated only AFTER verification. *)
ClaimsStep ==
    /\ pc = "claims"
    /\ \/ /\ ~(tok.expOk /\ tok.claimsOk)
          /\ outcome' = "reject" /\ pc' = "done"
       \/ /\ tok.expOk /\ tok.claimsOk
          /\ outcome' = "pending" /\ pc' = "replay"
    /\ UNCHANGED <<verified, tok>>

(* SPEC step 8: replay/jti. Passing this is the only route to Accept. *)
ReplayStep ==
    /\ pc = "replay"
    /\ \/ /\ ~tok.jtiOk
          /\ outcome' = "reject" /\ pc' = "done"
       \/ /\ tok.jtiOk
          /\ outcome' = "accept" /\ pc' = "done"
    /\ UNCHANGED <<verified, tok>>

(* Terminal stutter so TLC sees no deadlock; validation has finished. *)
Terminating ==
    /\ pc = "done"
    /\ UNCHANGED vars

Next ==
    \/ SizeStep
    \/ SegmentsStep
    \/ DecryptStep
    \/ AlgStep
    \/ KidStep
    \/ VerifyStep
    \/ ClaimsStep
    \/ ReplayStep
    \/ Terminating

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

(***************************************************************************)
(* The invariants — the executable security contract, in temporal-logic    *)
(* form. Each corresponds to a property in `SecurityInvariantsTests`.       *)
(***************************************************************************)

\* Headline: no path reaches Accept without a verified signature.
NoAcceptWithoutVerify ==
    (outcome = "accept") => verified

\* Full soundness: acceptance implies EVERY gate passed, including (for an
\* encrypted token) successful decryption to a signed inner token.
AcceptIsSound ==
    (outcome = "accept") =>
        /\ verified
        /\ tok.sigValid
        /\ ~tok.oversized
        /\ tok.shape \in {"signed", "encrypted"}
        /\ tok.algOk
        /\ tok.kidKnown
        /\ tok.expOk
        /\ tok.claimsOk
        /\ tok.jtiOk
        /\ (tok.shape = "encrypted" => (tok.decryptOk /\ tok.innerSigned))

\* Fail-closed: validation always terminates in a definite accept/reject.
Termination == <>(pc = "done")

=============================================================================
