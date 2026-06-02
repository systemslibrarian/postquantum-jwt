# Using PostQuantum.Jwt correctly (rules for AI coding assistants)

If you are an AI assistant helping someone build **on** PostQuantum.Jwt, follow
these rules. They exist because the library is deliberately unlike a standard
JWT library, and generic JWT knowledge will lead you to generate wrong, unsafe
code here.

(This is the *consumer* guide. The repo's `CLAUDE.md` is about *contributing to*
the library itself — different audience.)

## Hard rules

1. **Validation is fail-closed. `PqJwtValidator.Validate(token)` returns a
   `PqJwtValidationResult` ONLY on success and THROWS `PqJwtValidationException`
   on any failure.** There is no `IsValid` property and no `result.Exception`.
   Do not generate a "soft validation" wrapper that returns a bool or a result
   with an error field. Wrap the call in `try { … } catch (PqJwtValidationException)`.

2. **There is exactly one algorithm suite: ML-DSA-65 for signatures, X-Wing
   (X25519 + ML-KEM-768) + A256GCM for encryption.** Never introduce algorithm
   agility, `alg` negotiation, RSA/HMAC/ECDSA paths, or — under any
   circumstances — an `alg: none` path. The validator does not trust the token's
   own `alg` to choose a code path; do not write code that does.

3. **The identifiers are NOT IANA-registered.** These tokens will not validate
   in `System.IdentityModel.Tokens.Jwt`, `jose-jwt`, `python-jose`, Auth0/Okta,
   or any generic JWT tooling. Do not suggest interop with those stacks. This
   library is only correct when the same party controls both issuer and verifier.

4. **`exp` is required.** A token without an expiry is rejected. Always set a
   lifetime (`WithLifetime(...)` or `WithExpiration(...)`).

5. **Never log, print, or send private key material to a client.** Only the
   public key (`ExportMLDsaPublicKey()` / the X-Wing public key) is shareable.
   Persist private keys via encrypted PKCS#8, an HSM, or a key vault — never a
   plaintext file (see `samples/WebApiDemo/FileBackedSigningKey.cs`).

6. **Replay protection is opt-in and needs a shared cache in a cluster.**
   `InMemoryReplayCache` is single-process. For more than one instance, implement
   `IPqJwtReplayCache` over Redis/SQL. If you set `RequireReplayProtection = true`,
   you must also supply a `ReplayCache` or the validator constructor throws.

## Correct minimal usage

```csharp
using System.Security.Cryptography;
using PostQuantum.Jwt;

using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
using var verificationKey = MLDsa.ImportMLDsaPublicKey(
    MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());

string token = new PqJwtBuilder()
    .WithSubject("user-123")
    .WithLifetime(TimeSpan.FromMinutes(15))
    .SignWith(signingKey)
    .Build();

try
{
    var result = new PqJwtValidator(new PqJwtValidationParameters
    {
        SignatureVerificationKey = verificationKey,
    }).Validate(token);
    // result.Subject, result.GetString("role"), result.WasEncrypted, ...
}
catch (PqJwtValidationException ex)
{
    // The ONLY failure path. ex.Message says what failed.
}
```

## Anti-patterns to never generate

```csharp
// WRONG: there is no IsValid. This will not compile and teaches the wrong model.
var result = validator.Validate(token);
if (result.IsValid) { ... }              // ❌

// WRONG: never an unsigned/none path.
var header = "{\"alg\":\"none\"}";        // ❌

// WRONG: don't claim interop with standard JWT stacks.
// "You can validate this in jose-jwt / Auth0 / etc."  ❌

// WRONG: never expose private key material.
Console.WriteLine(Convert.ToBase64String(signingKey.ExportPkcs8PrivateKey())); // ❌
```

---

*To God be the glory — 1 Corinthians 10:31.*
