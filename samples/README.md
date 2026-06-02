# PostQuantum.Jwt — Samples

Runnable demonstrations of the [PostQuantum.Jwt](../README.md) library.

| Project              | What it is                                  | Best for                          |
| -------------------- | ------------------------------------------- | --------------------------------- |
| `ConsoleDemo`        | Menu-driven console app (Spectre.Console)   | Seeing every feature fast         |
| `WebApiDemo`         | Minimal ASP.NET Core API, `AddPqJwtBearer`  | Real service integration          |
| `VerifierDemo`       | Second service that verifies via the issuer's key directory | Cross-service key rotation |
| `PqJwtPlayground`    | Blazor Server interactive UI                | Building/validating in a browser  |
| `SpecByExample`      | xUnit tests whose names are the lessons     | Learning by stepping through code |
| `DistributedReplayCache` | Redis / IDistributedCache `IPqJwtReplayCache` | Multi-node replay defense |
| `TestingSupport`     | No-crypto test auth handler                 | Testing your own `[Authorize]` endpoints |
| `RefreshTokenDemo`   | Access/refresh split with rotation + reuse detection | Logout & revocation around the token |
| `Pq.Samples.Shared`  | Tiny shared library (`RejectionExplainer`)  | One source of truth for one thing |

All samples reference the local `src/` projects, so no NuGet install is needed
for development.

## For AI coding assistants

If you're using an AI assistant to build **on** this library, point it at
[`LLM-USAGE.md`](LLM-USAGE.md) (and [`.cursorrules`](.cursorrules)). Generic JWT
knowledge produces wrong code here — the library is fail-closed, single-suite,
and intentionally non-interoperable. Those files state the rules.

## Two-service demo (issuer + verifier)

[`docker-compose.yml`](docker-compose.yml) runs `WebApiDemo` (issuer) and
`VerifierDemo` (verifier) on an isolated network. The verifier validates the
issuer's tokens using public keys it fetches from `/.well-known/pqjwt-keys` —
no shared secret. Run from the repo root:

```bash
docker compose -f samples/docker-compose.yml up --build
```

## Key persistence

`WebApiDemo` generates an ephemeral key by default (and warns about it). Set
`PQJWT_KEY_PATH` to switch on persistence via
[`FileBackedSigningKey`](WebApiDemo/FileBackedSigningKey.cs), which shows the
real encrypted-PKCS#8 export/import lifecycle so tokens survive restarts.

## About `Pq.Samples.Shared`

The samples are otherwise self-contained. The one exception is
`RejectionExplainer`, which maps the validator's exception messages to
plain-language explanations and is coupled to the library's exact throw strings;
it lives in one small shared project so copies can't drift. Referenced by
`ConsoleDemo` and `PqJwtPlayground`. `WebApiDemo`/`VerifierDemo` don't use it —
their 401/403 responses deliberately don't tell a client why auth failed.

## Requirements

- .NET 10 SDK
- Native ML-KEM / ML-DSA support: **OpenSSL 3.5+** on Linux, or a recent
  Windows. Every sample fails closed with a clear error where these are absent.

## Run any sample

```bash
cd samples/ConsoleDemo     && dotnet run
cd samples/WebApiDemo      && dotnet run
cd samples/VerifierDemo    && dotnet run    # needs the issuer running on :5080
cd samples/PqJwtPlayground && dotnet run
cd samples/SpecByExample   && dotnet test
```

## Adding to the solution

```bash
dotnet sln PostQuantum.Jwt.slnx add \
  samples/Shared/Pq.Samples.Shared.csproj \
  samples/ConsoleDemo/ConsoleDemo.csproj \
  samples/WebApiDemo/WebApiDemo.csproj \
  samples/VerifierDemo/VerifierDemo.csproj \
  samples/PqJwtPlayground/PqJwtPlayground.csproj \
  samples/SpecByExample/SpecByExample.csproj
```

## Security guides

- **[SECURE-USAGE.md](SECURE-USAGE.md)** — the decisions *around* the token:
  minimal claims, in-memory access tokens (not localStorage), the refresh-token
  pattern, issuer/audience pinning, replay, key persistence.
- **[HARDENING-CHECKLIST.md](HARDENING-CHECKLIST.md)** — each classic JWT attack
  mapped to how this library blocks it (most are impossible by design).

## Library-level enhancements (separate from samples)

Two of these touch the LIBRARY, not the samples, so they live in `library-patches/`
at the bundle root rather than under `samples/`:

- **Validation metrics** — a reviewed patch to `src/PostQuantum.Jwt/PqJwtValidator.cs`
  adding OpenTelemetry-compatible counters (`pqjwt.validations`, tagged
  `outcome`/`reason`). Apply it, build, run the existing tests. See
  `library-patches/README-METRICS-PATCH.md`.
- **Roslyn analyzer** (`PostQuantum.Jwt.Analyzers`) — compile-time diagnostics
  (PQJWT001/PQJWT002) enforcing correct usage. A working starting point that
  needs a test project before shipping. See `library-patches/PostQuantum.Jwt.Analyzers/README.md`.

---

*To God be the glory — 1 Corinthians 10:31.*
