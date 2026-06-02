# PostQuantum.Jwt.Templates

`dotnet new` templates for [PostQuantum.Jwt](https://github.com/systemslibrarian/postquantum-jwt) —
scaffold a runnable starting point that signs with ML-DSA-65 and validates
fail-closed.

> **Preview release — not for production use.** See the library's
> [`KNOWN-GAPS.md`](https://github.com/systemslibrarian/postquantum-jwt/blob/main/KNOWN-GAPS.md).

## Install

```bash
dotnet new install PostQuantum.Jwt.Templates
```

## Templates

| Short name      | What you get |
| --------------- | ------------ |
| `pqjwt-webapi`  | A minimal ASP.NET Core API that issues and validates post-quantum JWTs via `AddPqJwtBearer`, with a JWKS-equivalent key directory. |
| `pqjwt-console` | A console app that signs a token and validates it fail-closed. |

## Use

```bash
# ASP.NET Core API
dotnet new pqjwt-webapi -n MyApi
cd MyApi && dotnet run

# console
dotnet new pqjwt-console -n MyApp
cd MyApp && dotnet run
```

The scaffolded projects reference the published `PostQuantum.Jwt` NuGet package.

> **Runtime note.** The native ML-DSA / ML-KEM primitives require **OpenSSL 3.5+**
> at runtime. The projects *compile* anywhere; they *run* where a recent OpenSSL
> is available.

For the full set of worked examples (refresh-token rotation, a distributed
replay cache, a Blazor playground, cross-service key rotation, and more), see the
[`samples/`](https://github.com/systemslibrarian/postquantum-jwt/tree/main/samples)
directory in the repository.

## Uninstall

```bash
dotnet new uninstall PostQuantum.Jwt.Templates
```

---

*To God be the glory — 1 Corinthians 10:31.*
