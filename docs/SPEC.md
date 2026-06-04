# PostQuantum.Jwt Token Profile v1

A normative description of the token profile this library produces and accepts.
Working notes on the construction live in [`design.md`](design.md); the security
model is in [`../SECURITY.md`](../SECURITY.md); known limitations are in
[`../KNOWN-GAPS.md`](../KNOWN-GAPS.md). Where this document and the code disagree,
the code is authoritative — please file an issue.

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used in the
RFC 2119 sense.

## Overview

| Field | Value |
|---|---|
| Profile name | PostQuantum.Jwt v1 |
| Token type | JOSE-style, controlled-system token (JWT-like compact serialization) |
| Intended environment | Owned issuer/verifier systems (same team controls both ends) |
| Signing algorithm | `ML-DSA-65` (FIPS 204; registered JOSE identifier, RFC 9964) |
| Optional confidentiality | `X-Wing` key agreement (X25519 + ML-KEM-768) + `A256GCM` |
| Serialization | JOSE compact: 3 segments (signed) or 5 segments (signed-then-encrypted) |

**Standards status.** `ML-DSA-65` and `A256GCM` are registered JOSE identifiers,
but the `X-Wing` key-management profile that ties them together here is **not** a
standardized JOSE/JWE profile. This profile is therefore for controlled
issuer/verifier systems, not generic JWT/JWE interoperability.

## Token structure

### Signed (3 segments)

```
BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)
```

- Protected header MUST be `{"alg":"ML-DSA-65","typ":"JWT"[,"kid":"…"]}`.
- `signature` = ML-DSA-65 signature over `ASCII(header "." payload)`.

### Signed-then-encrypted (5 segments)

```
BASE64URL(header) "." BASE64URL(kem_ct) "." BASE64URL(iv) "."
BASE64URL(ciphertext) "." BASE64URL(tag)
```

- Protected header MUST be `{"alg":"X-Wing","enc":"A256GCM","typ":"JWT","cty":"JWT"}`.
- The plaintext MUST be a complete 3-segment signed token (sign-then-encrypt).
- AAD MUST be `ASCII(BASE64URL(header))`; `iv` is a 12-byte GCM nonce; `tag` is
  the 16-byte GCM tag.

## Required protected-header fields

| Form | Required header members | Notes |
|---|---|---|
| Signed | `alg` = `ML-DSA-65`, `typ` = `JWT` | `kid` REQUIRED when key rotation is in use |
| Encrypted | `alg` = `X-Wing`, `enc` = `A256GCM`, `typ` = `JWT`, `cty` = `JWT` | wraps a signed token |

A verifier MUST NOT take a verification or decryption key from the token. The
only header members read are `alg`/`enc`/`typ`/`cty`/`kid`; `jwk`/`jku`/`x5u`/
`x5c` MUST be ignored.

## Claims

The library carries any JSON claims the issuer sets and enforces a subset (see
Validation). For a **production-oriented deployment** in this profile, issuers
SHOULD populate and verifiers SHOULD enforce:

| Claim | Profile expectation | Enforced by the library |
|---|---|---|
| `iss` | REQUIRED | Enforced when `ValidIssuer` is configured |
| `aud` | REQUIRED | Enforced when `ValidAudience` is configured |
| `sub` | REQUIRED | Carried; application asserts presence/meaning |
| `exp` | REQUIRED | Enforced by default (`RequireExpiration = true`) |
| `nbf` | RECOMMENDED | Enforced (with clock skew) when present |
| `iat` | RECOMMENDED | Carried; application MAY sanity-check |
| `jti` | REQUIRED when replay protection is enabled | Enforced when a replay cache is configured |

> **Honesty note.** The library does not expose `RequireIssuer` / `RequireSubject`
> / `RequireIssuedAt` switches. `exp` is required by default; `iss`/`aud` are
> enforced when you configure `ValidIssuer`/`ValidAudience`; `jti` uniqueness is
> enforced when you wire a replay cache. Mandating `sub`/`iat` and the *presence*
> of `iss`/`aud` is a deployment responsibility (configure the validator and add
> any application-level checks), not a separate library flag.

## Validation rules (fail-closed, in order)

A conforming verifier MUST apply checks in this order and MUST reject (throw)
rather than degrade on any failure:

1. **Pre-parse bounds.** Reject input over the maximum accepted length
   (128 KiB characters) before any split/decode/parse.
2. **Segment count.** Exactly 3 (signed) or 5 (encrypted); anything else is
   rejected.
3. **Decrypt (encrypted form only).** A decryption key MUST be configured; check
   `alg`/`enc`; X-Wing decapsulate; AES-256-GCM decrypt with the header as AAD.
   The nonce MUST be exactly 12 bytes and the tag exactly 16 bytes; any other
   length MUST be rejected. The tag length is taken from this profile, never from
   the token — AES-GCM accepts 12–16 byte tags, so honouring a shorter
   attacker-supplied tag would downgrade authentication strength and make the
   token malleable. A tag mismatch MUST reject. The result MUST be a 3-segment
   signed token.
4. **Algorithm.** `alg` MUST equal `ML-DSA-65`; any other value (including
   `none` or a missing `alg`) MUST be rejected. The verifier MUST NOT use the
   header `alg` to *select* a verification path — it accepts exactly one suite.
5. **Key selection.** When `kid` is present, resolve it through the configured
   `SignatureKeyResolver` / key ring. An unknown `kid` MUST be rejected. Key
   selection MUST NOT bypass the algorithm allowlist.
6. **Signature.** Verify the ML-DSA-65 signature; failure MUST reject.
7. **Claims.** Validate `exp` (required by default) and `nbf` within the
   configured clock skew (default 60s); validate `iss`/`aud` when configured. A
   present-but-malformed time claim MUST be rejected (not treated as absent).
8. **Replay.** When a replay cache is configured, the `jti` MUST be present and
   not previously seen; a missing `jti` or a repeat MUST be rejected.

## Explicitly rejected

- `alg: none`, missing `alg`, unknown `alg`, or any `alg` other than the
  configured suite.
- A `kid` that does not resolve, when key rotation is in use.
- Missing `exp` (unless `RequireExpiration` is explicitly disabled).
- A token whose `iss`/`aud` does not match the configured value.
- Expired tokens; `nbf` further in the future than the allowed clock skew.
- Malformed Base64Url; malformed JSON header or payload; a payload that is not a
  JSON object; a malformed time claim.
- **Non-canonical Base64Url** (RFC 7515 §2): embedded whitespace or non-zero
  "slack" bits in a segment's final character. Decoding is strict — exactly one
  base64url string maps to a given byte sequence — so token strings are
  non-malleable.
- Wrong segment count; truncated or oversized input.
- Invalid signature; invalid ciphertext authentication tag; modified AAD/header
  on encrypted tokens; decryption with the wrong recipient key.
- A repeated or missing `jti` when replay protection is required.

## Replay rules

- Replay protection is opt-in. With no replay cache configured, `jti` is carried
  but not enforced.
- Set `RequireReplayProtection = true` to fail closed at validator construction
  when no cache is wired.
- The bundled `InMemoryReplayCache` is development/single-process only.
  Multi-node deployments MUST use a distributed `IPqJwtReplayCache`
  (see `samples/DistributedReplayCache`).

## Key rotation rules

- Verifiers select a verification key from the token's `kid` via
  `SignatureKeyResolver` / `IPqJwtKeyRing`. The library does not fetch keys; the
  application owns the key ring.
- A verifier SHOULD accept the current and previous signing keys, retaining a
  retired verification key only for the longest accepted token lifetime.
- An unknown `kid` MUST fail closed. A `kid` MUST NOT be used as a file path or
  query.

## Size and clock-skew rules

- Maximum accepted token length: **128 KiB** characters (a hard pre-parse cap).
- Default clock skew: **60 seconds** (configurable; MUST be non-negative).

## Error-handling philosophy

Validation and decryption failures throw `PqJwtValidationException`;
misconfiguration throws `PqJwtException`. There is no soft/degraded result and no
"best effort" path. Token-derived values embedded in exception messages are
sanitized and length-capped; no token, key, or shared-secret material is logged.

## Compatibility with JWT/JWE

PostQuantum.Jwt uses JOSE-style concepts but **should not be assumed compatible
with generic JWT/JWE middleware.** Use the package's own `PqJwtValidator` (or an
explicit custom integration); do not expect `System.IdentityModel.Tokens.Jwt`,
`jose-jwt`, `node-jose`, `python-jose`, or OAuth/OIDC stacks to validate or
decrypt these tokens.

## Versioning

This is profile **v1**. A change to the wire format, header members, algorithm
suite, or validation order is a profile change and MUST be reflected here and in
the [`CHANGELOG`](../CHANGELOG.md).

---

*To God be the glory — 1 Corinthians 10:31.*
</content>
</invoke>
