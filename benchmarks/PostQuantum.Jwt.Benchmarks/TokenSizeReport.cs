using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using PostQuantum.Jwt.Cryptography;

namespace PostQuantum.Jwt.Benchmarks;

/// <summary>
/// Reports the on-the-wire size of the two token shapes this library produces.
/// Token <i>size</i> — not latency — is the headline cost of post-quantum JWTs:
/// an ML-DSA-65 signature alone is ~3.3 KB, an order of magnitude larger than an
/// ES256/EdDSA signature, so a PQ token is far bigger than a classical one. This
/// states that plainly with measured bytes rather than leaving it implied.
/// </summary>
public static class TokenSizeReport
{
    public static void Print(TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(output);

        using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var recipient = XWingPrivateKey.Generate();

        var signed = BuildSigned(signingKey);
        var encrypted = BuildEncrypted(signingKey, recipient.PublicKey);

        var signatureBytes = signingKey.SignData(Encoding.ASCII.GetBytes("size-probe")).Length;
        var classical = BuildClassicalEs256();

        output.WriteLine("PostQuantum.Jwt — token size report");
        output.WriteLine("====================================");
        output.WriteLine($"Classical ES256 JWT (baseline)     : {Utf8Bytes(classical),7:N0} bytes / {classical.Length,7:N0} chars");
        output.WriteLine($"ML-DSA-65 signature                : {signatureBytes,7:N0} bytes (raw)");
        output.WriteLine($"Signed token (3-part compact)      : {Utf8Bytes(signed),7:N0} bytes / {signed.Length,7:N0} chars");
        output.WriteLine($"Signed+encrypted token (5-part)    : {Utf8Bytes(encrypted),7:N0} bytes / {encrypted.Length,7:N0} chars");
        output.WriteLine();
        output.WriteLine($"Post-quantum overhead vs. classical: signed ≈ {(double)Utf8Bytes(signed) / Utf8Bytes(classical):F1}x, " +
                         $"encrypted ≈ {(double)Utf8Bytes(encrypted) / Utf8Bytes(classical):F1}x the ES256 baseline.");
        output.WriteLine("Baseline is ES256 (ECDSA P-256) via the modern JsonWebTokenHandler, same claims.");
        output.WriteLine();
        output.WriteLine("To God be the glory — 1 Corinthians 10:31.");
    }

    private static int Utf8Bytes(string value) => Encoding.UTF8.GetByteCount(value);

    private static string BuildClassicalEs256()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var key = new ECDsaSecurityKey(ecdsa);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://bench.postquantum.jwt",
            Audience = "benchmark-audience",
            Expires = DateTime.UtcNow.AddHours(1),
            Claims = new Dictionary<string, object> { ["sub"] = "benchmark-subject" },
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256),
        });
    }

    private static string BuildSigned(MLDsa signingKey) =>
        new PqJwtBuilder()
            .WithIssuer("https://bench.postquantum.jwt")
            .WithSubject("benchmark-subject")
            .WithAudience("benchmark-audience")
            .WithLifetime(TimeSpan.FromHours(1))
            .SignWith(signingKey)
            .Build();

    private static string BuildEncrypted(MLDsa signingKey, XWingPublicKey recipient) =>
        new PqJwtBuilder()
            .WithIssuer("https://bench.postquantum.jwt")
            .WithSubject("benchmark-subject")
            .WithAudience("benchmark-audience")
            .WithLifetime(TimeSpan.FromHours(1))
            .SignWith(signingKey)
            .EncryptFor(recipient)
            .Build();
}
