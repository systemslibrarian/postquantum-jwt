# How validation fails closed

`PqJwtValidator` runs **8 checks, in order**, and **throws** rather than degrade on the first failure. There is no unsigned path and no algorithm negotiation — exactly one suite is accepted.

1. **Pre-parse bounds** — reject oversized input before parsing.
2. **Segment count** — exactly 3 or 5.
3. **Decrypt** *(encrypted only)* — X-Wing decapsulate, AES-256-GCM with the header as AAD; a tag mismatch rejects.
4. **Algorithm** — `alg` must equal `ML-DSA-65`; `none`/missing/other rejects.
5. **Key selection** — resolve `kid` through the configured key ring; unknown `kid` rejects.
6. **Signature** — verify the ML-DSA-65 signature.
7. **Claims** — `exp` (required by default) and `nbf` within clock skew; `iss`/`aud` when configured.
8. **Replay** — when a cache is configured, `jti` must be present and unseen.

The **Validation flow** view shows each step, what it checks, and exactly what makes it reject.
