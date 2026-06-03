# PostQuantum.Jwt — Web API Demo

A minimal ASP.NET Core API showing real integration via the
**PostQuantum.Jwt.AspNetCore** companion package (`AddPqJwtBearer`).

## Endpoints

| Method | Route                          | Purpose                                  |
| ------ | ------------------------------ | ---------------------------------------- |
| POST   | `/token?sub=&role=`            | Issue a signed ML-DSA-65 token ("login") |
| GET    | `/me`                          | Protected — requires a valid PQ JWT      |
| GET    | `/admin`                       | Protected — requires `role=admin`        |
| GET    | `/.well-known/pqjwt-keys`      | Key directory (JWKS-equivalent)          |

## Key lifecycle — read this first

**This demo generates a brand-new signing key every time the process starts.**
Every restart invalidates every token issued before it. That is deliberate for
a zero-config demo, and it is exactly what a real service must *not* do. The app
logs a loud `Warning` at startup so this is impossible to miss.

A production issuer instead loads a **persisted, securely-stored** key (HSM, key
vault, sealed file) so tokens survive restarts and rotation is explicit. The
issuer's signing key and its public verification half are created once at
startup and captured in closures, so the trust relationship (this key signs;
this key verifies) lives in one readable place in `Program.cs`.

## Quick start

```bash
cd samples/WebApiDemo
dotnet run
```

Then, in another terminal:

```bash
# 1) Get a token
TOKEN=$(curl -s -X POST "http://localhost:5080/token?sub=alice&role=admin" | jq -r .token)

# 2) Call the protected endpoint
curl -s http://localhost:5080/me -H "Authorization: Bearer $TOKEN" | jq

# 3) Admin-only
curl -s http://localhost:5080/admin -H "Authorization: Bearer $TOKEN" | jq

# 4) Public key directory
curl -s http://localhost:5080/.well-known/pqjwt-keys | jq

# 5) See the secure 401 (no token) — note the correlationId
curl -s http://localhost:5080/me | jq
```

(`WebApiDemo.http` has the same calls for VS / VS Code REST Client.)

## Logging & error responses

- Every request gets an `X-Correlation-ID` (honored from the inbound header or
  generated), logged in a scope alongside method, path, status, and latency —
  so the demo reads like a real service.
- `401`/`403` return RFC 7807 `application/problem+json` with that correlation
  id. They deliberately do **not** explain *why* auth failed (that would leak
  validator internals to an attacker); the operator matches the id to the logs.

## Multi-service key rotation

For separate issuer and verifier services, point `HttpPqJwtKeyRing` at the
issuer's `/.well-known/pqjwt-keys` URL and feed its `Resolve` into
`SignatureKeyResolver`:

```csharp
builder.Services.AddHttpClient();
builder.Services.AddSingleton<IPqJwtKeyRing>(sp =>
    new HttpPqJwtKeyRing(
        sp.GetRequiredService<IHttpClientFactory>().CreateClient(),
        new Uri("https://issuer.example/.well-known/pqjwt-keys"),
        refreshInterval: TimeSpan.FromMinutes(5)));

// in AddPqJwtBearer(...):
options.ValidationParameters = new PqJwtValidationParameters
{
    SignatureKeyResolver = kid =>
        sp.GetRequiredService<IPqJwtKeyRing>().Resolve(kid),
    ValidIssuer = "...", ValidAudience = "...",
};
```

The directory shape this demo serves —
`{ "keys": [ { "kid", "alg", "key" } ] }` — is exactly what that key ring reads,
and entries whose `alg` isn't `ML-DSA-65` are ignored (single-suite policy).
**Rotation flow:** mint with a new `kid`, publish *both* old and new keys here
during the overlap window, and verifiers pick up the new key on their next
refresh — no redeploy, and in-flight old-kid tokens keep validating until they
expire.

## Docker

> **OpenSSL 3.5+ is required for the PQ primitives.** No current .NET base image
> ships it — Ubuntu 24.04 is on OpenSSL 3.0 and even Azure Linux 3.0 is only on
> 3.3.5 — so the app would start but **fail closed** on every ML-KEM / ML-DSA op.
> This Dockerfile brings **OpenSSL 3.5 via conda-forge** and points the runtime
> loader at it (the same approach the playground Dockerfile and the repo's CI use).

Build from the **repository root** (the Dockerfile references `../../src`):

```bash
docker build -f samples/WebApiDemo/Dockerfile -t pqjwt-webapidemo .
docker run --rm -p 5080:8080 pqjwt-webapidemo
```

## Notes

- **DEMO ONLY.** See the key-lifecycle section above.
- Don't also call `AddJwtBearer` — the standard handler can't parse `ML-DSA-65`.
- Production-oriented preview, not audited; non-standardized X-Wing key-management profile; tokens not interoperable with generic JWT/JWE tooling.

## Persisting the signing key (surviving restarts)

By default this demo generates a new key per process — fine for a demo, wrong
for production. Set `PQJWT_KEY_PATH` to switch on persistence:

```bash
PQJWT_KEY_PATH=./keys/issuer.pkcs8 \
PQJWT_KEY_PASSPHRASE=change-me \
dotnet run
```

Now the key is generated once, written as **encrypted PKCS#8**, and reloaded on
every subsequent start — so tokens issued before a restart keep validating.
[`FileBackedSigningKey.cs`](FileBackedSigningKey.cs) shows the real lifecycle
(`ExportEncryptedPkcs8PrivateKey` / `ImportEncryptedPkcs8PrivateKey`, owner-only
file mode) and is honest that a file still isn't an HSM or key vault.

---

*To God be the glory — 1 Corinthians 10:31.*
