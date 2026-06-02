# PostQuantum.Jwt — Interactive Playground (Blazor Server)

A browser UI for building and validating post-quantum JWTs in real time, built
to *teach* — not just to demo the happy path.

## Features

- **Build**: set sub/iss/aud, lifetime, and custom claims; toggle X-Wing
  encryption and `jti`. Custom claims use a safe name/value editor — values are
  typed automatically (`true`/`false` → bool, integers → long, decimals →
  number, else string), so there's no fragile raw-JSON box and no AOT-unsafe
  reflection path in the hot loop.
- **Validate**: paste any token; fail-closed result with claims and timing.
- **"Why was this rejected?"**: when validation fails, the UI explains the
  failure in plain language (e.g. *"The token was altered after signing"*),
  with the raw validator message tucked behind a "technical detail" disclosure.
  This is the highest-value part of the playground.
- **Size comparison**: the measured PQ token size against representative
  HS256 / ES256 / EdDSA tokens, on a shared scale.
- **"What this protects against"**: a callout covering forgery, algorithm
  downgrade, harvest-now-decrypt-later, and replay — plus an honest pair of
  *not*-protected items (interop, audited assurance).
- **Session keys**: view the ML-DSA-65 and X-Wing public keys; regenerate.

## Why Blazor Server (not WASM)

The ML-DSA / ML-KEM primitives need a real .NET 10 runtime with **OpenSSL 3.5+**
and do not run in the browser. All crypto executes server-side; **private keys
never leave the server**. WASM support for these primitives is still maturing.

## Quick start

```bash
cd samples/PqJwtPlayground
dotnet run
```

Open the printed HTTPS URL (e.g. https://localhost:7100).

## Requirements

- .NET 10 SDK
- OpenSSL 3.5+ (Linux) or recent Windows for the native PQ primitives

## Docker

See the `Dockerfile` (build from the repository root). Uses Azure Linux 3.0 for
a new-enough OpenSSL.

## Hosting note

This is a stateful Blazor Server app. To put it on `systemslibrarian.dev`, host
it on a runtime that provides OpenSSL 3.5+ (a container on a VM, Azure Container
Apps, etc.). It cannot run as a static GitHub Pages site, because the crypto is
server-side by necessity.

## Accessibility

Sections are labelled (`aria-labelledby`), inputs carry `aria-label`s, the
result panel is a live `status` region, and the layout collapses to a single
column on narrow screens.

## Notes

- Demo keys are per-process and in-memory; regenerating invalidates old tokens.
- Preview software, not audited; non-IANA identifiers; non-interoperable tokens.

---

*To God be the glory — 1 Corinthians 10:31.*
