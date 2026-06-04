# PostQuantum.Jwt for VS Code

[![Marketplace Version](https://img.shields.io/visual-studio-marketplace/v/systemslibrarian.postquantum-jwt?label=marketplace&color=blue)](https://marketplace.visualstudio.com/items?itemName=systemslibrarian.postquantum-jwt)
[![Installs](https://img.shields.io/visual-studio-marketplace/i/systemslibrarian.postquantum-jwt?color=blue)](https://marketplace.visualstudio.com/items?itemName=systemslibrarian.postquantum-jwt)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/systemslibrarian/postquantum-jwt/blob/main/LICENSE)

The companion extension for the [**PostQuantum.Jwt**](https://www.nuget.org/packages/PostQuantum.Jwt) .NET library — ML-DSA-65 signatures with optional X-Wing hybrid confidentiality (X25519 + ML-KEM-768 + AES-256-GCM), for controlled .NET issuer/verifier systems.

It helps you both **write** and **understand** post-quantum JWTs: a visual token inspector, diagrams of the hybrid construction and validation flow, snippets, hovers, and a one-click jump to the live playground.

> **This extension does no cryptography.** It inspects the compact-serialization structure and the unencrypted protected header only. Encrypted payloads stay encrypted — it never signs, validates, encrypts, or decrypts. Anything that touches real keys happens in the browser playground or your own code.

## What's new in 0.2

- 🔍 **Visual Token Inspector** — a rich webview that color-codes each segment, decodes the header, lists claims, and flags the expected algorithm identifiers. Distinguishes 3-segment **signed** from 5-segment **encrypted** tokens at a glance.
- 🧩 **Hybrid Construction view** — a step-by-step diagram of sign → X-Wing encapsulate → AES-256-GCM, including the X-Wing combiner, so the sign-then-encrypt design is intuitive.
- 🛡️ **Validation Flow view** — the validator's 8 fail-closed checks, in order, with exactly what makes each one reject.
- 🚀 **Smarter playground link** — "Open in Playground" reconstructs the build form (issuer, audience, claims, lifetime) from a signed token and deep-links it.
- 📚 **Walkthrough** — a guided "Understand post-quantum JWTs" tour in *Get Started*.

## Install

- **Extensions view:** open Extensions (`Ctrl+Shift+X` / `Cmd+Shift+X`), search **PostQuantum.Jwt**, and click *Install*.
- **Quick Open:** press `Ctrl+P` / `Cmd+P` and run `ext install systemslibrarian.postquantum-jwt`.
- **Command line:** `code --install-extension systemslibrarian.postquantum-jwt`

Or install from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=systemslibrarian.postquantum-jwt) page.

## Features

### 🔍 Visual Token Inspector

Run **PostQuantum.Jwt: Inspect Token (Visual)** — or click the **🔍 Inspect PQ-JWT** CodeLens above any token — to open the inspector. It has three tabs:

**Token** — the token, with each segment color-coded by role:

| Form | Segments | Lanes |
| --- | --- | --- |
| **Signed** | 3 | `header` · `payload` · `signature` |
| **Encrypted** | 5 | `header` · `kem_ct` · `iv` · `ciphertext` · `tag` |

Each segment expands to show decoded JSON (header/payload) or its byte length and role (opaque bytes). Algorithm **badges** confirm `ML-DSA-65` / `X-Wing` / `A256GCM`, the claims set is shown as a table (registered claims tagged), and `alg: none` is called out as a hard rejection. Encrypted payloads are clearly marked — they are never decrypted.

**Hybrid construction** — the three steps that build an encrypted token, with the X-Wing combiner:

```
ss = SHA3-256( ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label )
```

**Validation flow** — the validator's ordered, fail-closed checks (bounds → segments → decrypt → algorithm → key → signature → claims → replay), each with the reasons it rejects. Steps annotate themselves against the loaded token (e.g. *decrypt* is marked "not for signed tokens").

You can also jump straight to a view: **Show Hybrid Construction Diagram** and **Show Validation Flow** (they use your selection if it's a token, otherwise a sample).

### ≡ Text decode

Prefer plain text? **PostQuantum.Jwt: Decode Token (Text)** (or the **≡ Text decode** CodeLens) opens a read-only report — the same structure/header analysis without the webview.

### 🚀 Open in Playground (pre-filled)

From the inspector, **Open in Playground ▸** reconstructs the playground's build form from a signed token's claims (subject, issuer, audience, lifetime, jti, and custom claims) and deep-links it. No keys or secrets are ever encoded — only the claim form. Encrypted tokens (opaque payload) open the playground plainly.

### Snippets (C#)

Type a prefix and tab through a fully-formed example:

| Prefix | Inserts |
| --- | --- |
| `pqjwt-quick` | The 60-second sign + validate tour |
| `pqjwt-sign` | Sign with issuer/audience/claims, then validate |
| `pqjwt-encrypt` | Sign-then-encrypt for an X-Wing recipient |
| `pqjwt-rotate` | `kid` key rotation + `jti` replay protection |
| `pqjwt-aspnetcore` | `AddPostQuantumJwtBearer` ASP.NET Core wiring |
| `pqjwt-keyring` | `HttpPostQuantumJwtKeyRing` (JWKS-equivalent) |
| `pqjwt-install` | `<PackageReference>` for the library |

### Hover & CodeLens

Hover `PqJwtBuilder`, `PqJwtValidator`, `XWingPrivateKey`, and friends in a `.cs` file for a one-line description, a short concept note, and a jump to the relevant docs section. API symbols and inline tokens get CodeLenses (toggle with `pqjwt.codeLens.enabled`).

### Inline detection

In a `.cs`, `.json`, or `.http` file, a token gets **🔍 Inspect** / **≡ Text decode** CodeLenses. Detection is deliberately strict: a string is only flagged when it has 3 or 5 segments **and** its protected header decodes to this suite's `alg` (`ML-DSA-65` or `X-Wing`), so version strings, hashes, and ordinary base64 blobs don't trigger it.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `pqjwt.codeLens.enabled` | `true` | Show the inline Inspect / docs CodeLenses. |
| `pqjwt.inspector.openToSide` | `true` | Open the inspector beside the editor instead of replacing it. |

## Commands

`PostQuantum.Jwt:` → Inspect Token (Visual) · Decode Token (Text) · Show Hybrid Construction Diagram · Show Validation Flow · Open Live Playground · Open Docs · Open on NuGet · Open GitHub Repository · Generate a Key Pair (in Playground).

## Try it without installing anything

The library is .NET 10 only and needs OpenSSL 3.5+ for the native PQ primitives. To build and break a real token in your browser with no install, use the **[live playground](https://pqjwt.systemslibrarian.dev)**.

> PostQuantum.Jwt is a production-oriented preview for controlled systems — **not** independently audited, and **not** a drop-in OAuth/OIDC/JWT replacement. Its tokens intentionally do not interoperate with generic JWT tooling.

## Privacy

This extension sends **no telemetry**, and **decodes tokens entirely locally** — your tokens are never uploaded to inspect them. Snippets, token decoding, the visual inspector, and the hover/CodeLens helpers all run **on your machine**, and the inspector webview is sandboxed with a strict Content-Security-Policy (no remote origins; scripts run only with a per-render nonce).

The only data that leaves your machine is when **you** click a link:

- **Open in Playground** on a *signed* token reconstructs the playground's build form from that token's **decoded claims** (subject, issuer, audience, lifetime, `jti`, and any custom claims) and encodes them into the link, so the playground can pre-fill them. **Those claim values travel in the URL to the playground** — the button says *"sends decoded claims"* when this applies, and the playground regenerates its own keys (no key material is ever encoded). Encrypted tokens have an opaque payload and open the playground plainly.
- The other links (docs, NuGet, GitHub, plain playground) carry no token data.

If you don't want any claim values to leave your machine, don't use *Open in Playground* on a token whose claims are sensitive.

## Build from source

```bash
cd tools/vscode
npm ci
npm run compile        # tsc → out/
npm run lint
npm test               # unit tests (node:test)
npx @vscode/vsce package   # → postquantum-jwt-<version>.vsix
```

The extension is plain TypeScript with **no runtime dependencies**; the webview is built from static assets in `media/`. See [`MONOREPO-SETUP.md`](MONOREPO-SETUP.md) for how it lives inside the library repo.

## License

MIT.

---

*To God be the glory — 1 Corinthians 10:31.*
