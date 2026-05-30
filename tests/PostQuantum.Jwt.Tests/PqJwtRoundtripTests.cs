using System.Text.Json;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.Tests;

public sealed class PqJwtRoundtripTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    [PqcFact]
    public void Signed_token_round_trips_with_all_standard_claims()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithIssuer("https://issuer.example")
            .WithSubject("user-123")
            .WithAudience("https://api.example")
            .WithJwtId("token-1")
            .WithClaim("role", "admin")
            .WithLifetime(TimeSpan.FromMinutes(30))
            .SignWith(signingKey)
            .Build();

        Assert.Equal(3, token.Split('.').Length);

        var result = Validator(signingKey, clock, iss: "https://issuer.example", aud: "https://api.example")
            .Validate(token);

        Assert.False(result.WasEncrypted);
        Assert.Equal("https://issuer.example", result.Issuer);
        Assert.Equal("user-123", result.Subject);
        Assert.Equal("token-1", result.JwtId);
        Assert.Equal("admin", result.GetString("role"));
        Assert.Equal(Now.AddMinutes(30), result.ExpiresAt);
    }

    [PqcFact]
    public void Encrypted_token_round_trips_and_reports_encryption()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("secret-subject")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        Assert.Equal(5, token.Split('.').Length);

        var parameters = new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = recipient,
        };
        var result = new PqJwtValidator(parameters, clock).Validate(token);

        Assert.True(result.WasEncrypted);
        Assert.Equal("secret-subject", result.Subject);
    }

    [PqcFact]
    public void Tampered_signature_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = SimpleToken(signingKey, clock);

        // Flip a character in the signature segment.
        var parts = token.Split('.');
        parts[2] = parts[2][..^1] + (parts[2][^1] == 'A' ? 'B' : 'A');
        var tampered = string.Join('.', parts);

        Assert.Throws<PqJwtValidationException>(() => Validator(signingKey, clock).Validate(tampered));
    }

    [PqcFact]
    public void Tampered_payload_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithClaim("role", "user")
            .WithLifetime(TimeSpan.FromMinutes(10))
            .SignWith(signingKey)
            .Build();

        // Re-encode a payload that claims admin without re-signing.
        var forgedPayload = Convert.ToBase64String("{\"role\":\"admin\"}"u8)
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var parts = token.Split('.');
        var forged = $"{parts[0]}.{forgedPayload}.{parts[2]}";

        Assert.Throws<PqJwtValidationException>(() => Validator(signingKey, clock).Validate(forged));
    }

    [PqcFact]
    public void Expired_token_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var issueClock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(issueClock)
            .WithLifetime(TimeSpan.FromMinutes(1))
            .SignWith(signingKey)
            .Build();

        var laterClock = new FixedTimeProvider(Now.AddMinutes(10));
        var ex = Assert.Throws<PqJwtValidationException>(() => Validator(signingKey, laterClock).Validate(token));
        Assert.Contains("expired", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Token_without_expiration_is_rejected_by_default()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock).WithSubject("no-exp").SignWith(signingKey).Build();

        Assert.Throws<PqJwtValidationException>(() => Validator(signingKey, clock).Validate(token));
    }

    [PqcFact]
    public void Wrong_audience_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithAudience("https://other.example")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        Assert.Throws<PqJwtValidationException>(
            () => Validator(signingKey, clock, aud: "https://api.example").Validate(token));
    }

    [PqcFact]
    public void A_token_verified_with_the_wrong_key_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var otherKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = SimpleToken(signingKey, clock);

        Assert.Throws<PqJwtValidationException>(() => Validator(otherKey, clock).Validate(token));
    }

    [PqcFact]
    public void Encrypted_token_without_decryption_key_throws_configuration_error()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        // Missing DecryptionKey: a usage error, not a validation failure.
        var ex = Assert.Throws<PqJwtException>(() => Validator(signingKey, clock).Validate(token));
        Assert.IsNotType<PqJwtValidationException>(ex);
    }

    [Fact]
    public void Build_without_a_signing_key_throws()
    {
        var ex = Assert.Throws<PqJwtException>(() => new PqJwtBuilder().WithSubject("x").Build());
        Assert.Contains("signing key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Malformed_token_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var parameters = new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            ValidateLifetime = false,
        };
        Assert.Throws<PqJwtValidationException>(
            () => new PqJwtValidator(parameters).Validate("only.two"));
    }

    private static string SimpleToken(System.Security.Cryptography.MLDsa key, TimeProvider clock) =>
        new PqJwtBuilder(clock)
            .WithSubject("subject")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(key)
            .Build();

    private static PqJwtValidator Validator(
        System.Security.Cryptography.MLDsa signingKey,
        TimeProvider clock,
        string? iss = null,
        string? aud = null) =>
        new(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                ValidIssuer = iss,
                ValidAudience = aud,
            },
            clock);
}
