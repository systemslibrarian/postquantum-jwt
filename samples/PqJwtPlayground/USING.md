# How to use the Post-Quantum JWT Playground

**Live:** <https://pqjwt.systemslibrarian.dev>

The playground lets you build and validate post-quantum JWTs in your browser and
*see* the fail-closed design behave — no install, no keys to manage. All crypto
runs server-side on .NET 10 + OpenSSL 3.5; the keys are per-session and in memory.

> The first load after the demo's been idle can take up to a minute to wake (it's
> hosted scale-to-zero to keep costs near zero). If it doesn't respond, give it a
> moment and reload.

## 1 · Build a token

Fill in what you want the token to carry:

- **Subject / Issuer / Audience** — identity claims (`sub`/`iss`/`aud`). Leave any blank to skip it.
- **Lifetime** — sets `iat` and the required `exp`.
- **Encrypt (X-Wing)** — wraps the signed token in X25519 + ML-KEM-768 + AES-256-GCM, so the payload is *confidential*, not just tamper-evident.
- **jti** — adds a unique token id (needed if you want to demo replay protection).
- **Custom claims** — add name/value rows; values are typed automatically (`true`→bool, `42`→number, otherwise string).

Click **Create token**. You'll see the decoded header and payload, plus a **size
bar** comparing the post-quantum token against classical HS256 / ES256 / EdDSA.
Hit **Send to validator ↓** to drop it into the next section.

## 2 · Validate a token

Paste any token (or the one you just built) and click **Validate**:

- **Valid** → you get the claims, whether it was encrypted, and the timing.
- **Invalid** → it fails closed with a plain-language **"Why was this rejected?"** (the raw validator reason is tucked behind "technical detail").

**Try breaking it:** build a token, change a single character in the middle
(payload) segment, and validate — watch it get rejected as a signature mismatch.
Or give a token a short lifetime, let it expire, and validate again.

## 3 · Session keys

See this session's **public** ML-DSA-65 and X-Wing keys (the private keys never
leave the server). **Regenerate** to roll them — tokens signed with the old key
then stop validating, which is key rotation in miniature.

## 4 · What this protects against

A quick map of the guarantees — forgery, algorithm downgrade, harvest-now/
decrypt-later, replay — alongside an honest note on what it does **not** give you
(interoperability with standard JWT stacks, an independent audit).

## Good to know

- Keys are per-session and in memory; **regenerating, or a server restart, invalidates old tokens** by design.
- `ML-DSA-65` and `A256GCM` are registered JOSE identifiers, but the `X-Wing` key-management profile that ties them together here is **not** a standardized JOSE/JWE profile, so these tokens **will not validate or decrypt in generic JWT tooling** — that's deliberate; the library is for when you control both issuer and verifier.
- Production-oriented preview, unaudited — for controlled issuer/verifier systems, not a drop-in OAuth/OIDC/JWT replacement.

## Use it in your own code

The playground is one of several [samples](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples).
To build on the library: `dotnet add package PostQuantum.Jwt`, and point your AI
assistant at [LLM-USAGE.md](https://github.com/systemslibrarian/postquantum-jwt/blob/main/samples/LLM-USAGE.md)
so it generates correct, fail-closed code.

---

*To God be the glory — 1 Corinthians 10:31.*
