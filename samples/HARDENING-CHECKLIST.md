# JWT attack → how PostQuantum.Jwt blocks it

A defensive map of the classic JWT attacks (the ones in every bug-bounty guide)
against this library's behavior. The recurring theme: most of these are
*impossible by design* here, not "mitigated if configured." Where a row depends
on you, it says so.

| # | Attack | Blocked? | Why / what you must do |
| - | ------ | -------- | ---------------------- |
| 1 | **`alg: none`** (strip the signature) | By design | There is no unsigned code path. The validator requires `ML-DSA-65` and verifies a real signature; a `none`/missing signature can't validate. |
| 2 | **Algorithm confusion** (RS256→HS256, sign with the public key as HMAC secret) | By design | One suite only. The validator does not trust the token's `alg` to pick a verification path, and ML-DSA is asymmetric — there is no symmetric secret to confuse it with. |
| 3 | **Weak HMAC secret** (brute-force `secret`/`password123`) | By design | No shared secret exists. Signing is ML-DSA-65 (asymmetric); there is nothing to crack offline. |
| 4 | **No expiration / `exp` not checked** | By design (default) | `exp` is validated, and `RequireExpiration` rejects tokens lacking it. Keep `ValidateLifetime` on. |
| 5 | **No revocation** (stateless token lives until expiry) | Architecture | A bare access token can't be revoked — that's inherent to stateless JWTs. Use short lifetimes + the refresh/rotation pattern (`RefreshTokenDemo/`) for real logout. |
| 6 | **Sensitive data in payload** (PII/role readable) | Your choice | Signed payloads are readable. Carry only `sub`; look up the rest server-side (`SECURE-USAGE.md`). Use `EncryptFor` if you need confidentiality. |
| 7 | **`kid` injection** (kid → SQL/path traversal) | By design + your resolver | `kid` is passed to *your* `SignatureKeyResolver` as an opaque lookup value; the library never feeds it to a query or file path. Don't build an injection into your own resolver — look it up in a fixed map / key ring. |
| 8 | **Role manipulation** (edit payload to `role: admin`) | By design | Editing any byte of the payload breaks the ML-DSA signature; validation fails closed. (And if you followed #6, there's no `role` in the token to edit.) |
| 9 | **Missing signature verification** (decode but don't verify) | By design | `Validate()` always verifies the signature before returning; there is no decode-only path. It throws on failure rather than returning a degraded result. |
| 10 | **Token replay** (reuse a captured token) | Opt-in | Set `RequireReplayProtection = true` + a `ReplayCache` (distributed across nodes — `DistributedReplayCache/`). Requires a `jti`. |
| 11 | **Cross-service token acceptance** | Your config | Pin `ValidIssuer` and `ValidAudience` so a token minted elsewhere isn't accepted here. |
| 12 | **Token theft via `localStorage` + XSS** | Architecture | Not a token property — keep the access token in memory and the refresh token in an `HttpOnly` cookie (`SECURE-USAGE.md`, `RefreshTokenDemo/`). |
| 13 | **Token sniffed over plain HTTP** | Your transport | A token is a bearer credential. Terminate TLS (and HSTS for browsers); never send a token over `http://`. |
| 14 | **Token leaked via logs** | By design + your config | The library logs nothing; the ASP.NET Core handler logs only the failure *reason*, never the token or key bytes. On your side, redact `Authorization`/`Cookie` headers in request logging (`SECURE-USAGE.md` §8). |
| 15 | **Token leaked via URL / query string** | Your config | Query strings end up in history, proxy/server access logs, and `Referer` headers. Send tokens in the `Authorization` header or an `HttpOnly` cookie — never `?token=`. |
| 16 | **Header key injection** (`jwk` / `jku` / `x5u` / `x5c` — attacker embeds their own key, or a URL to it, in the header) | By design | The validator never takes a verification key from the token. It reads only `alg`/`enc`/`typ`/`cty`/`kid` from the header; keys come **solely** from your `SignatureVerificationKey` or `SignatureKeyResolver(kid)`. A `jwk`/`jku`/`x5u` is ignored, so a token "signed by its own embedded key" can't validate, and there is no header-driven URL fetch to redirect. |
| 17 | **`kid` path-traversal / LFI** (`"kid": "../../dev/null"`) | By design + your resolver | `kid` is an opaque string handed to *your* resolver; the library never uses it as a file path or query. Resolve it through a fixed in-memory map / key ring (see #7). |
| 18 | **CPU exhaustion via verification flood** (post-quantum signatures cost more to verify than classical, so forcing verifications is a DoS vector) | By design + your config | The validator runs the **cheap checks first**: a wrong `alg`, an unknown `kid`, or malformed encoding/JSON is rejected *before* any ML-DSA verification — so a flood of garbage costs little and surfaces as `algorithm_not_accepted` / `unknown_kid` / `malformed_*`. Only a well-formed token for a known `kid` reaches the expensive verify (a `signature_mismatch` spike). Reuse one `PqJwtValidator` (it's immutable and thread-safe — don't construct per request), rate-limit unauthenticated endpoints, and alert on that meter spike. |
| 19 | **Token-type / purpose confusion** (a token minted for one purpose — access vs refresh vs verification — accepted where another is expected) | Your config | The validator proves a token is authentic and its claims valid; it does not know what the token is *for*. Bind each token kind to a distinct `ValidAudience` (or a purpose claim you check), and keep refresh tokens opaque (not PqJwts) so they can't be replayed as access tokens (`SECURE-USAGE.md` §3–4). |
| 20 | **Malformed `exp` / `nbf` treated as absent** (e.g. `"exp": "..."` or a fractional number) | By design | A present-but-malformed time claim is rejected (`malformed_time_claim`), not silently ignored — it can't bypass not-before or turn into an immortal token. |
| 21 | **Log injection via crafted header/claim** (CRLF in `alg`/`kid`/`jti` to forge log lines) | By design | The validator sanitizes any token-derived value before embedding it in an exception message — control characters are stripped and the value is length-capped — so logging a rejection can't inject or forge log lines. |
| 22 | **Pre-parse resource exhaustion** (a multi-megabyte "token" to amplify decode/verify work) | By design | A token over a generous fixed length cap (128 KB; ~20× the largest real token) is rejected *before* any split, Base64Url decode, JSON parse, or ML-DSA verification. |

## Detecting attacks: what shows up in metrics

Every rejection is counted on the `pqjwt.validations` meter (emitted via
`System.Diagnostics.Metrics`; wire it to OpenTelemetry or any meter listener),
tagged `outcome="failure"` and a coarse, non-sensitive `reason` taken from the
typed `PqJwtFailureReason` on the exception — never the token, claims, or key
material. So the attacks above aren't just blocked, they're *observable*:

| Attack (rows above) | `reason` tag | What a spike means |
| ------------------- | ------------ | ------------------ |
| `alg: none`, algorithm confusion (1, 2) | `algorithm_not_accepted` | Someone is sending non-suite tokens — probing for a downgrade. |
| Role manipulation, forged/missing signature (8, 9) | `signature_mismatch` | **Active forgery attempts** — the highest-signal alert here. |
| Expired / missing `exp` (4) | `expired`, `missing_exp` | Clock drift, or replayed stale tokens. |
| Unknown `kid` (7) | `unknown_kid` | A retired/never-issued key id — rotation lag or probing. |
| Token replay (10) | `replay_detected`, `missing_jti` | A captured token is being reused. |
| Cross-service token (11) | `issuer_mismatch`, `audience_mismatch` | A token minted elsewhere is being presented here. |

```csharp
builder.Services.AddOpenTelemetry().WithMetrics(m => m
    .AddMeter("PostQuantum.Jwt")     // the validator's meter
    .AddPrometheusExporter());       // or OTLP, console, etc.
```

Alert on `pqjwt.validations{outcome="failure",reason="signature_mismatch"}`
climbing — that's a live forgery signal, surfaced without logging anything
sensitive.

## Authentication is not authorization

Note what is **not** in the table: IDOR, broken access control, privilege
escalation *after* a valid login, and business-logic flaws. Those are the other
half of the bug-bounty playbook — and this library does **nothing** to stop them,
by design. A validated token proves **who** the caller is; deciding **what** they
may do is your application's job. Even a perfectly signed token saying
`sub: alice` does not let alice read `/api/orders/999` unless your code checks.
Enforce object-level and function-level authorization on every request,
server-side. Carry only `sub` in the token and look up roles/permissions
server-side (`SECURE-USAGE.md`); a `role: admin` claim is only ever as trustworthy
as your decision to put it there.

## Production-readiness checklist

Before using PostQuantum.Jwt in a controlled production system, confirm each:

- [ ] You control both the issuer and every verifier.
- [ ] You are **not** using this as public OAuth/OIDC middleware.
- [ ] You have read [`SECURITY.md`](../SECURITY.md) and [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).
- [ ] You accept that the construction has **not** received an independent cryptographic audit.
- [ ] Issuer (`ValidIssuer`) and audience (`ValidAudience`) validation are enabled.
- [ ] Expiration is required (`RequireExpiration`); token lifetimes are short.
- [ ] Not-before / clock-skew behavior is understood and acceptable.
- [ ] Only the configured algorithm suite is accepted; unknown/`none` `alg` fails closed (this is by design).
- [ ] Replay protection is configured (`RequireReplayProtection = true` + a `ReplayCache`) where one-time use matters.
- [ ] The replay cache is **distributed** if more than one node validates tokens (the in-memory cache is dev-only).
- [ ] Signing keys are rotated on a schedule; old verification keys are retained only for the longest accepted token lifetime.
- [ ] Private keys are encrypted at rest and never committed to source control.
- [ ] `kid` resolution uses a fixed key ring/map (never a file path or query built from `kid`).
- [ ] Logs never contain raw tokens, private keys, shared secrets, or decrypted sensitive claims.
- [ ] TLS is enforced everywhere; tokens are never sent over `http://` or in query strings.
- [ ] CI passes, including the negative/fail-closed tests; dependency scanning is enabled.
- [ ] A vulnerability-disclosure process exists (see [`SECURITY.md`](../SECURITY.md)).

After completing this checklist, the honest claim you can make is:
**"Production-oriented preview for controlled systems. Not independently
audited."** Avoid "production-grade crypto", "audited", "battle-tested", or
"drop-in OIDC replacement".

## The honest caveat

This library is a **production-oriented preview** — **unaudited** — and ties its
registered JOSE identifiers (`ML-DSA-65`, `A256GCM`) together with an `X-Wing`
key-management profile that is **not** a standardized JOSE/JWE profile. Its
tokens are therefore deliberately **non-interoperable** with standard JWT/JWE
stacks. It's the right tool only when you control both issuer and verifier. That
non-interoperability is itself a hardening property against tooling that expects
standard JWTs, but it is a deliberate trade-off, not a free lunch.

---

*To God be the glory — 1 Corinthians 10:31.*
