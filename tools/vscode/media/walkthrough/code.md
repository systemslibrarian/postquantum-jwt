# Write the code

In a C# file, type a prefix and press <kbd>Tab</kbd> to expand a working example:

| Prefix | Inserts |
| --- | --- |
| `pqjwt-quick` | The 60-second sign + validate tour |
| `pqjwt-sign` | Sign with issuer/audience/claims, then validate |
| `pqjwt-encrypt` | Sign-then-encrypt for an X-Wing recipient |
| `pqjwt-rotate` | `kid` key rotation + `jti` replay protection |
| `pqjwt-aspnetcore` | `AddPostQuantumJwtBearer` ASP.NET Core wiring |
| `pqjwt-keyring` | `HttpPostQuantumJwtKeyRing` (JWKS-equivalent) |
| `pqjwt-install` | `<PackageReference>` for the library |

Hover any `PqJwt…` / `XWing…` symbol for a one-line explainer and a jump to the docs. When you want to sign or validate for real, open the **[live playground](https://pqjwt.systemslibrarian.dev)** — the library is .NET 10 only and needs OpenSSL 3.5+.
