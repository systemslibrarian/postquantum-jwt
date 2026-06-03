# PostQuantum.Jwt for VS Code

Companion extension for the [**PostQuantum.Jwt**](https://www.nuget.org/packages/PostQuantum.Jwt) .NET library — ML-DSA-65 signatures with optional X-Wing hybrid confidentiality (X25519 + ML-KEM-768 + AES-256-GCM), for controlled .NET issuer/verifier systems.

This extension does **no cryptography**. It helps you *write* and *understand* PostQuantum.Jwt code, and points you at the live playground for anything that actually signs or validates.

## Install

Search **PostQuantum.Jwt** in the VS Code Extensions view, or install from the command line:

```
ext install systemslibrarian.postquantum-jwt
```

Also on the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=systemslibrarian.postquantum-jwt).

## Features

### Snippets (C#)
Type a prefix and tab through a fully-formed example:

| Prefix | Inserts |
| --- | --- |
| `pqjwt-quick` | The 60-second sign + validate tour |
| `pqjwt-sign` | Sign with issuer/audience/claims, then validate |
| `pqjwt-encrypt` | Sign-then-encrypt for an X-Wing recipient |
| `pqjwt-rotate` | `kid` key rotation + `jti` replay protection |
| `pqjwt-aspnetcore` | `AddPostQuantumJwtBearer` ASP.NET Core wiring |
| `pqjwt-keyring` | `HttpPqJwtKeyRing` (JWKS-equivalent) |
| `pqjwt-install` | `<PackageReference>` for the library |

### Decode Token
Select a token (or run the command and paste one) → **PostQuantum.Jwt: Decode Token**. It splits the compact serialization, shows whether it's the 3-part **signed** or 5-part **encrypted** form, decodes the protected header, and flags the expected `ML-DSA-65` / `X-Wing` / `A256GCM` identifiers. Structure and headers only — encrypted claims stay encrypted.

### Quick links
Command palette → "PostQuantum.Jwt:" → open the **Live Playground**, **Docs**, **NuGet**, **GitHub**, or **Generate a Key Pair** (in the playground).

### Hover & CodeLens
Hover `PqJwtBuilder`, `PqJwtValidator`, `XWingPrivateKey`, and friends in a `.cs` file for a one-line description plus a jump to the relevant docs section.

## Try it without installing anything

The library is .NET 10 only and needs OpenSSL 3.5+ for the native PQ primitives. To build and break a real token in your browser with no install, use the **[live playground](https://pqjwt.systemslibrarian.dev)**.

> PostQuantum.Jwt is a production-oriented preview for controlled systems — **not** independently audited, and **not** a drop-in OAuth/OIDC/JWT replacement. Its tokens intentionally do not interoperate with generic JWT tooling.

## License

MIT.

---

*To God be the glory — 1 Corinthians 10:31.*
