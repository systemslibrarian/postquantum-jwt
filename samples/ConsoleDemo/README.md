# PostQuantum.Jwt — Console Demo

An interactive, menu-driven console app that exercises every core feature of
**PostQuantum.Jwt** and shows the library's fail-closed behavior in action.

## What it demonstrates

- ML-DSA-65 signatures (FIPS 204)
- Optional hybrid encryption with X-Wing (X25519 + ML-KEM-768) → AES-256-GCM
- Replay protection with `InMemoryReplayCache`
- Key rotation via a `kid` resolver
- Real token sizes and timings
- **Attack mode** — a guided walk through six realistic forgery attempts, each
  rejected, each with a plain-language explanation of *why*:
  1. Privilege escalation (edit the `role` claim, reuse the signature)
  2. Algorithm confusion (`alg: none` substitution)
  3. Forgery with an attacker's own key
  4. Expired token
  5. Token with no `exp`
  6. Replay of a one-time token

The privilege-escalation case is a *real* tamper: it decodes the payload,
rewrites `role` to `admin`, re-encodes, and leaves the original signature in
place — so the failure is genuinely "signature verification failed," not a
base64 parse error. That is the lesson: the signature, not the transport, is
what stops the forgery.

## Quick start

```bash
cd samples/ConsoleDemo
dotnet run
```

Start with option **1** (generate a keypair), then try **2**, **3**, **4**, and **7**.

## Requirements

- .NET 10 SDK
- Native ML-KEM / ML-DSA support: **OpenSSL 3.5+** on Linux, or a recent
  Windows. Without it the PQ paths fail closed with a clear error.

## Notes

- All keys live only in memory for the session; nothing is persisted.
- Private key material is never printed — only the public key is exportable.
- This is **preview software** and the construction is **not audited**.
- Tokens use a non-standardized X-Wing key-management profile and will not validate or decrypt in generic JWT tooling.

## Next steps

- `samples/WebApiDemo` — real ASP.NET Core integration with `AddPqJwtBearer`
- `samples/PqJwtPlayground` — interactive Blazor Server UI

---

*To God be the glory — 1 Corinthians 10:31.*
