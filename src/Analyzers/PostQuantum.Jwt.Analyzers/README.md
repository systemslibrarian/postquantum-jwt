# PostQuantum.Jwt.Analyzers

Compile-time enforcement of [PostQuantum.Jwt](https://github.com/systemslibrarian/postquantum-jwt)'s
fail-closed architecture. Because the library deliberately breaks classical JWT
conventions (single ML-DSA-65 suite, header ignored for key selection), generic
JWT linters don't fit — these analyzers encode the library's actual rules.

> **Preview release — not for production use.**

## Install

```xml
<PackageReference Include="PostQuantum.Jwt.Analyzers" Version="1.0.0-preview.2" PrivateAssets="all" />
```

`PrivateAssets="all"` keeps the analyzer a build-time-only dependency (it never
flows to your package's consumers).

## Rules

| ID | Severity | Flags |
| -- | -------- | ----- |
| **PQJWT001** | Error | Reading a JOSE header field (`alg`, `jwk`, `jku`, `x5u`, `x5c`) from a `System.Text.Json` `JsonElement.GetProperty/TryGetProperty` or `JsonNode`/`JsonObject` indexer. The verification key comes from a trusted key ring keyed by `kid`, never the token header — inspecting the header reintroduces algorithm-confusion and `jwk`/`jku` key-injection attacks. Call `PqJwtValidator.Validate(...)` instead. |
| **PQJWT002** | Warning | `new PqJwtValidator(...).Validate(...)` — constructing a validator per call. It's immutable and thread-safe; cache one instance (a field, singleton, or DI registration). |

Both rules are semantic (type-aware), so they don't fire on unrelated JSON or on
the correct singleton/DI patterns.

## Tuning severity

Adjust per project in `.editorconfig`:

```ini
# Relax PQJWT001 to a warning, or elevate PQJWT002 to an error
dotnet_diagnostic.PQJWT001.severity = warning
dotnet_diagnostic.PQJWT002.severity = error
```

Suppress a single justified case with `#pragma warning disable PQJWT001` or
`[SuppressMessage("Security", "PQJWT001")]`.

---

*To God be the glory — 1 Corinthians 10:31.*
