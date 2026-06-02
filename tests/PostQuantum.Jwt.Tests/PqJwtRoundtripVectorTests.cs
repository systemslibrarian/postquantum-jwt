using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Internal;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Pinned end-to-end roundtrip corpus
/// (<c>TestVectors/jwt-roundtrip-vectors.json</c>). Each vector fixes the
/// deterministic parts of a built token — the compact JSON of the protected
/// header and (for signed shapes) the payload — and asserts:
/// <list type="bullet">
/// <item>The builder emits exactly that compact JSON.</item>
/// <item>The token validates successfully end-to-end.</item>
/// </list>
/// </summary>
/// <remarks>
/// <para>
/// What is intentionally <b>not</b> pinned: the ML-DSA-65 signature bytes
/// (BCL <c>SignData(byte[])</c> is randomized), the X-Wing KEM ciphertext
/// (ML-KEM <c>Encapsulate</c> is randomized — see <c>KNOWN-GAPS.md</c>),
/// and the AES-GCM nonce / ciphertext / tag (per-encryption-fresh nonce).
/// The base64url envelope is verified implicitly by decoding each pinned
/// segment back to UTF-8 JSON and comparing.
/// </para>
/// </remarks>
public sealed class PqJwtRoundtripVectorTests
{
    private static readonly JsonSerializerOptions VectorJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public static TheoryData<string, RoundtripVector> Vectors()
    {
        var json = File.ReadAllText(Path.Combine("TestVectors", "jwt-roundtrip-vectors.json"));
        var vectors = JsonSerializer.Deserialize<List<RoundtripVector>>(json, VectorJsonOptions)
            ?? throw new InvalidOperationException("Could not load JWT roundtrip vectors.");

        var data = new TheoryData<string, RoundtripVector>();
        foreach (var vector in vectors)
        {
            data.Add(vector.Name, vector);
        }

        return data;
    }

    [PqcTheory]
    [MemberData(nameof(Vectors))]
    [SuppressMessage("Security", "CA5394:Do not use insecure randomness", Justification = "ML-DSA signing key generation uses the BCL's secure RNG; this attribute does not apply to MLDsa.GenerateKey.")]
    public void Vector_round_trips_with_pinned_deterministic_parts(string name, RoundtripVector vector)
    {
        _ = name;

        var clock = new FixedTimeProvider(DateTimeOffset.FromUnixTimeSeconds(vector.ClockUnixSeconds));

        using var signingKey = TestKeys.NewSigningKey();
        using var verificationKey = TestKeys.PublicKeyOf(signingKey);

        // Builder call order matters for the pinned payload: claims are
        // appended in insertion order, and WithLifetime adds `iat` then
        // `exp`. The vectors expect key order
        // [iss, sub, aud, jti, <custom>, iat, exp] so primitives go first
        // and WithLifetime is last. WithKeyId touches the header only, so
        // its position is free.
        var builder = new PqJwtBuilder(clock).SignWith(signingKey);
        if (!string.IsNullOrEmpty(vector.Issuer)) builder = builder.WithIssuer(vector.Issuer!);
        if (!string.IsNullOrEmpty(vector.Subject)) builder = builder.WithSubject(vector.Subject!);
        if (!string.IsNullOrEmpty(vector.Audience)) builder = builder.WithAudience(vector.Audience!);
        if (!string.IsNullOrEmpty(vector.JwtId)) builder = builder.WithJwtId(vector.JwtId!);
        if (vector.StringCustomClaims is { } customs)
        {
            foreach (var (k, v) in customs)
            {
                builder = builder.WithClaim(k, v);
            }
        }
        if (!string.IsNullOrEmpty(vector.Kid)) builder = builder.WithKeyId(vector.Kid!);
        builder = builder.WithLifetime(TimeSpan.FromSeconds(vector.LifetimeSeconds));

        XWingPrivateKey? decryptionKey = null;
        try
        {
            string token;
            if (string.Equals(vector.Shape, "encrypted", StringComparison.Ordinal))
            {
                decryptionKey = XWingPrivateKey.Generate();
                builder = builder.EncryptFor(decryptionKey.PublicKey);
                token = builder.Build();
            }
            else
            {
                token = builder.Build();
            }

            var parts = token.Split('.');
            var expectedSegments = string.Equals(vector.Shape, "encrypted", StringComparison.Ordinal) ? 5 : 3;
            Assert.Equal(expectedSegments, parts.Length);

            // Pinned header bytes (UTF-8 inside the base64url envelope).
            var headerJson = Encoding.UTF8.GetString(Base64Url.Decode(parts[0]));
            Assert.Equal(vector.ExpectedHeaderJson, headerJson);

            // For signed shapes, also pin the payload bytes. For encrypted
            // shapes, the inner payload is sealed behind AES-GCM and cannot
            // be pinned without decrypting; the validator path covers that
            // round-trip below.
            if (vector.ExpectedPayloadJson is not null)
            {
                var payloadJson = Encoding.UTF8.GetString(Base64Url.Decode(parts[1]));
                Assert.Equal(vector.ExpectedPayloadJson, payloadJson);
            }

            // End-to-end validation.
            var parameters = new PqJwtValidationParameters
            {
                SignatureVerificationKey = verificationKey,
                ValidIssuer = string.IsNullOrEmpty(vector.Issuer) ? null : vector.Issuer,
                ValidAudience = string.IsNullOrEmpty(vector.Audience) ? null : vector.Audience,
                DecryptionKey = decryptionKey,
            };
            var result = new PqJwtValidator(parameters, clock).Validate(token);

            Assert.Equal(
                string.Equals(vector.Shape, "encrypted", StringComparison.Ordinal),
                result.WasEncrypted);
            if (!string.IsNullOrEmpty(vector.Subject)) Assert.Equal(vector.Subject, result.Subject);
            if (!string.IsNullOrEmpty(vector.JwtId)) Assert.Equal(vector.JwtId, result.JwtId);
        }
        finally
        {
            decryptionKey?.Dispose();
        }
    }
}

public sealed class RoundtripVector
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("shape")]
    public string Shape { get; init; } = "signed";

    [JsonPropertyName("clock_unix_seconds")]
    public long ClockUnixSeconds { get; init; }

    [JsonPropertyName("lifetime_seconds")]
    public int LifetimeSeconds { get; init; }

    [JsonPropertyName("kid")]
    public string? Kid { get; init; }

    [JsonPropertyName("issuer")]
    public string? Issuer { get; init; }

    [JsonPropertyName("subject")]
    public string? Subject { get; init; }

    [JsonPropertyName("audience")]
    public string? Audience { get; init; }

    [JsonPropertyName("jwt_id")]
    public string? JwtId { get; init; }

    [JsonPropertyName("string_custom_claims")]
    public Dictionary<string, string>? StringCustomClaims { get; init; }

    [JsonPropertyName("expected_header_json")]
    public string ExpectedHeaderJson { get; init; } = "";

    [JsonPropertyName("expected_payload_json")]
    public string? ExpectedPayloadJson { get; init; }
}
