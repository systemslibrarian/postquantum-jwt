// PostQuantum.Jwt — sign and validate a post-quantum JWT.
//
// NOTE: the native ML-DSA / ML-KEM primitives require OpenSSL 3.5+ at runtime.

using System.Security.Cryptography;
using PostQuantum.Jwt;

// Generate an ML-DSA-65 signing key. A real service loads a persisted key
// (HSM, key vault, sealed file) instead of generating one per run.
using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
using var verificationKey = MLDsa.ImportMLDsaPublicKey(
    MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());

// Issue a signed post-quantum JWT.
string token = new PqJwtBuilder()
    .WithIssuer("https://issuer.example")
    .WithAudience("https://api.example")
    .WithSubject("user-123")
    .WithClaim("role", "reader")
    .WithLifetime(TimeSpan.FromMinutes(15))
    .WithJwtId(Guid.NewGuid().ToString("N"))
    .SignWith(signingKey)
    .Build();

Console.WriteLine($"Issued token ({token.Length} chars):\n{token}\n");

// Validate it. PostQuantum.Jwt is fail-closed: Validate returns ONLY on success,
// otherwise it throws PqJwtValidationException. There is no alg:none path and no
// "best effort" result — a rejected token is an exception, never a return value.
try
{
    var result = new PqJwtValidator(new PqJwtValidationParameters
    {
        SignatureVerificationKey = verificationKey,
        ValidIssuer = "https://issuer.example",
        ValidAudience = "https://api.example",
    }).Validate(token);

    Console.WriteLine(
        $"Valid. sub={result.Subject}, role={result.GetString("role")}, " +
        $"encrypted={result.WasEncrypted}, expires={result.ExpiresAt:u}");
}
catch (PqJwtValidationException ex)
{
    // Catch the SPECIFIC validation type — not Exception or the PqJwtException
    // base — so genuine misconfiguration isn't swallowed as a normal rejection.
    Console.Error.WriteLine($"Rejected: {ex.Message}");
    Environment.Exit(1);
}
