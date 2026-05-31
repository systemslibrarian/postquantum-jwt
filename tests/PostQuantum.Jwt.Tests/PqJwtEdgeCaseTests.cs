using System.Text;
using System.Text.Json;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Locks in the fail-closed behavior for the long tail of malformed, malicious,
/// or just-unusual tokens. Every test here exists to keep a real failure mode
/// from regressing — a green run means the validator still refuses what it
/// must refuse.
/// </summary>
public sealed class PqJwtEdgeCaseTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    [PqcFact]
    public void Not_before_in_the_future_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var issueClock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(issueClock)
            .WithNotBefore(Now.AddMinutes(10))
            .WithLifetime(TimeSpan.FromMinutes(30))
            .SignWith(signingKey)
            .Build();

        var validateClock = new FixedTimeProvider(Now); // before nbf
        var ex = Assert.Throws<PqJwtValidationException>(
            () => Validator(signingKey, validateClock).Validate(token));
        Assert.Contains("not valid before", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Not_before_within_clock_skew_is_accepted()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var issueClock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(issueClock)
            .WithNotBefore(Now.AddSeconds(30)) // 30s in the future — inside the 60s default skew
            .WithLifetime(TimeSpan.FromMinutes(10))
            .SignWith(signingKey)
            .Build();

        var validateClock = new FixedTimeProvider(Now);
        var result = Validator(signingKey, validateClock).Validate(token);
        Assert.False(result.WasEncrypted);
    }

    [PqcFact]
    public void Expired_token_within_clock_skew_is_accepted()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var issueClock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(issueClock)
            .WithLifetime(TimeSpan.FromMinutes(1))
            .SignWith(signingKey)
            .Build();

        // 30 seconds past expiry — still within the default 60s skew window.
        var laterClock = new FixedTimeProvider(Now.AddSeconds(60 + 30));
        var result = Validator(signingKey, laterClock).Validate(token);
        Assert.NotNull(result);
    }

    [PqcFact]
    public void Audience_array_with_matching_entry_is_accepted()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        // RFC 7519 §4.1.3 allows aud to be a JSON array. The builder normally
        // writes a single string; serialize a multi-audience token directly to
        // confirm the validator accepts the array form.
        var aud = new[] { "https://other.example", "https://api.example" };
        var token = SignedTokenWithClaim(signingKey, clock, "aud", aud);

        var result = Validator(signingKey, clock, aud: "https://api.example").Validate(token);
        Assert.NotNull(result);
    }

    [PqcFact]
    public void Audience_array_without_matching_entry_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var aud = new[] { "https://a.example", "https://b.example" };
        var token = SignedTokenWithClaim(signingKey, clock, "aud", aud);

        Assert.Throws<PqJwtValidationException>(
            () => Validator(signingKey, clock, aud: "https://api.example").Validate(token));
    }

    [PqcFact]
    public void Wrong_algorithm_in_header_is_rejected_without_running_crypto()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        // Re-encode the header with a forged alg. The validator must reject
        // BEFORE attempting to verify with a different algorithm.
        var parts = token.Split('.');
        var forgedHeader = ToBase64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}"u8);
        var forged = $"{forgedHeader}.{parts[1]}.{parts[2]}";

        var ex = Assert.Throws<PqJwtValidationException>(() => Validator(signingKey, clock).Validate(forged));
        Assert.Contains("signature algorithm", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Header_without_alg_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var parts = token.Split('.');
        var forgedHeader = ToBase64Url("{\"typ\":\"JWT\"}"u8);
        var forged = $"{forgedHeader}.{parts[1]}.{parts[2]}";

        var ex = Assert.Throws<PqJwtValidationException>(() => Validator(signingKey, clock).Validate(forged));
        Assert.Contains("'alg'", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Header_with_invalid_json_is_rejected_as_validation_failure()
    {
        var goodSegment = ToBase64Url("{}"u8);
        var token = $"{ToBase64Url("not json"u8)}.{goodSegment}.{goodSegment}";

        using var signingKey = TestKeys.NewSigningKey();
        var parameters = new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            ValidateLifetime = false,
        };
        Assert.Throws<PqJwtValidationException>(() => new PqJwtValidator(parameters).Validate(token));
    }

    [PqcFact]
    public void Payload_that_is_a_json_array_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var validHeader = ToBase64Url("{\"alg\":\"ML-DSA-65\",\"typ\":\"JWT\"}"u8);
        var arrayPayload = ToBase64Url("[1,2,3]"u8);

        // Sign the bad payload with the real signing key so we know the rejection
        // is about *shape*, not signature.
        var signingInput = Encoding.ASCII.GetBytes($"{validHeader}.{arrayPayload}");
        var signature = ToBase64Url(signingKey.SignData(signingInput));
        var token = $"{validHeader}.{arrayPayload}.{signature}";

        var ex = Assert.Throws<PqJwtValidationException>(
            () => Validator(signingKey, clock).Validate(token));
        Assert.Contains("json object", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Encrypted_token_with_wrong_content_encryption_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        // Forge an outer header that advertises an unsupported content encryption.
        var parts = token.Split('.');
        var forgedHeader = ToBase64Url("{\"alg\":\"X-Wing\",\"enc\":\"A128GCM\",\"typ\":\"JWT\",\"cty\":\"JWT\"}"u8);
        var forged = $"{forgedHeader}.{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}";

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = recipient,
        }, clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(forged));
        Assert.Contains("content-encryption", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Encrypted_token_decryption_with_wrong_private_key_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var trueRecipient = XWingPrivateKey.Generate();
        using var wrongRecipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("for-eyes-only")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(trueRecipient.PublicKey)
            .Build();

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = wrongRecipient,
        }, clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Contains("decryption failed", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Encrypted_token_with_tampered_ciphertext_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        var parts = token.Split('.');
        parts[3] = parts[3][..^1] + (parts[3][^1] == 'A' ? 'B' : 'A');
        var tampered = string.Join('.', parts);

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = recipient,
        }, clock);

        Assert.Throws<PqJwtValidationException>(() => validator.Validate(tampered));
    }

    [PqcFact]
    public void Replay_protection_applies_to_encrypted_tokens()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);
        var cache = new InMemoryReplayCache(clock);

        var token = new PqJwtBuilder(clock)
            .WithJwtId("unique-encrypted")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = recipient,
            ReplayCache = cache,
        }, clock);

        Assert.True(validator.Validate(token).WasEncrypted);
        Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
    }

    [PqcFact]
    public void Custom_claims_round_trip_as_json_elements()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("subject")
            .WithClaim("scope", new[] { "read", "write" })
            .WithClaim("level", 7)
            .WithClaim("flag", true)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var result = Validator(signingKey, clock).Validate(token);

        Assert.Equal(JsonValueKind.Array, result.Claims["scope"].ValueKind);
        Assert.Equal(2, result.Claims["scope"].GetArrayLength());
        Assert.Equal(7, result.Claims["level"].GetInt32());
        Assert.True(result.Claims["flag"].GetBoolean());
    }

    [PqcFact]
    public void Claim_set_to_null_removes_a_previously_set_value()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("subject")
            .WithClaim("temporary", "to-be-removed")
            .WithClaim("temporary", null) // remove
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var result = Validator(signingKey, clock).Validate(token);
        Assert.False(result.Claims.ContainsKey("temporary"));
    }

    [PqcFact]
    public void XWing_private_key_throws_after_dispose()
    {
        var key = XWingPrivateKey.Generate();
        key.Dispose();

        Assert.Throws<ObjectDisposedException>(() => key.Export());
    }

    [PqcFact]
    public void XWing_double_dispose_is_safe()
    {
        var key = XWingPrivateKey.Generate();
        key.Dispose();
        key.Dispose(); // must not throw
    }

    [PqcFact]
    public void XWing_private_key_import_round_trips_byte_for_byte()
    {
        using var original = XWingPrivateKey.Generate();
        var exported = original.Export();

        using var restored = XWingPrivateKey.Import(exported);
        var reExported = restored.Export();

        Assert.Equal(exported, reExported);
    }

    [Fact]
    public void XWing_seed_of_wrong_length_is_rejected()
    {
        Assert.Throws<PqJwtException>(() => XWingPrivateKey.ImportSeed(new byte[16]));
        Assert.Throws<PqJwtException>(() => XWingPrivateKey.ImportSeed(new byte[64]));
    }

    [PqcFact]
    public void Encrypted_token_missing_cty_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        // Drop cty from the outer header; everything else stays valid.
        var parts = token.Split('.');
        var forgedHeader = ToBase64Url("{\"alg\":\"X-Wing\",\"enc\":\"A256GCM\",\"typ\":\"JWT\"}"u8);
        var forged = $"{forgedHeader}.{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}";

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = recipient,
        }, clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(forged));
        Assert.Contains("cty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Encrypted_token_with_wrong_cty_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        var parts = token.Split('.');
        var forgedHeader = ToBase64Url("{\"alg\":\"X-Wing\",\"enc\":\"A256GCM\",\"typ\":\"JWT\",\"cty\":\"text/plain\"}"u8);
        var forged = $"{forgedHeader}.{parts[1]}.{parts[2]}.{parts[3]}.{parts[4]}";

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = recipient,
        }, clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(forged));
        Assert.Contains("cty", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Negative_clock_skew_is_rejected_at_construction_time()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var parameters = new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            ClockSkew = TimeSpan.FromSeconds(-1),
        };
        Assert.Throws<ArgumentOutOfRangeException>(() => new PqJwtValidator(parameters));
    }

    [Fact]
    public void Validator_without_a_verification_key_or_resolver_throws_at_construction()
    {
        var parameters = new PqJwtValidationParameters();
        var ex = Assert.Throws<ArgumentException>(() => new PqJwtValidator(parameters));
        Assert.Contains("SignatureVerificationKey", ex.Message, StringComparison.Ordinal);
    }

    [PqcFact]
    public void Length_correct_but_structurally_invalid_X_Wing_public_key_fails_at_Import()
    {
        // 1216 random bytes — passes the length check, must fail the ML-KEM-768
        // parse that XWingPublicKey.Import now runs eagerly.
        var garbage = new byte[XWingPublicKey.EncodedLength];
        new Random(42).NextBytes(garbage);

        var ex = Assert.Throws<PqJwtException>(() => XWingPublicKey.Import(garbage));
        Assert.Contains("ML-KEM-768", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InMemoryReplayCache_under_concurrent_load_registers_each_jti_exactly_once()
    {
        var cache = new InMemoryReplayCache();
        var jtis = Enumerable.Range(0, 200).Select(i => $"jti-{i}").ToArray();
        var expires = DateTimeOffset.UtcNow.AddMinutes(5);

        // Each jti is attempted from many threads in parallel. Exactly one of the
        // attempts for each jti must succeed; the rest must report replay=false.
        var successesPerJti = new System.Collections.Concurrent.ConcurrentDictionary<string, int>();
        Parallel.ForEach(
            from jti in jtis
            from _ in Enumerable.Range(0, 8)
            select jti,
            jti =>
            {
                if (cache.TryRegister(jti, expires))
                {
                    successesPerJti.AddOrUpdate(jti, 1, (_, v) => v + 1);
                }
            });

        foreach (var jti in jtis)
        {
            Assert.True(successesPerJti.TryGetValue(jti, out var n), $"{jti} never registered");
            Assert.Equal(1, n);
        }
    }

    [PqcFact]
    public void Empty_token_string_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            ValidateLifetime = false,
        });
        Assert.Throws<ArgumentException>(() => validator.Validate(""));
    }

    [PqcFact]
    public void Token_with_four_segments_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            ValidateLifetime = false,
        });
        Assert.Throws<PqJwtValidationException>(() => validator.Validate("a.b.c.d"));
    }

    [Fact]
    public void Builder_requires_ML_DSA_65_signing_key()
    {
        // Other ML-DSA parameter sets must be refused — single-suite policy.
        if (!System.Security.Cryptography.MLDsa.IsSupported)
        {
            return;
        }

        using var wrongSize = System.Security.Cryptography.MLDsa.GenerateKey(
            System.Security.Cryptography.MLDsaAlgorithm.MLDsa44);

        var ex = Assert.Throws<PqJwtException>(() =>
            new PqJwtBuilder().SignWith(wrongSize));
        Assert.Contains("ML-DSA-65", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Builder_requires_positive_lifetime()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new PqJwtBuilder().WithLifetime(TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new PqJwtBuilder().WithLifetime(TimeSpan.FromSeconds(-1)));
    }

    [Fact]
    public void Builder_requires_non_empty_kid()
    {
        Assert.Throws<ArgumentException>(() => new PqJwtBuilder().WithKeyId(""));
    }

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

    [PqcFact]
    public void Malformed_base64_in_segment_is_wrapped_as_PqJwtValidationException()
    {
        // Lock in the v0.3.0-preview.2 contract: Base64 parse errors that
        // would previously leak as FormatException are now wrapped as
        // PqJwtValidationException, so callers see a single fail-closed
        // family. PostQuantum.AspNetCore depends on this — its handler
        // catches PqJwtException and now no longer needs the
        // catch-everything fallback for adversarial inputs.
        using var signingKey = TestKeys.NewSigningKey();
        // Three segments (signed-shape), all invalid Base64 — '!' is not
        // a valid base64url character. The Split('.') sees 3 parts;
        // Base64Url.DecodeToUtf8 throws FormatException; the validator
        // catches and rewraps.
        const string token = "!!!.!!!.!!!";
        var ex = Assert.Throws<PqJwtValidationException>(
            () => Validator(signingKey, new FixedTimeProvider(Now)).Validate(token));
        Assert.IsType<FormatException>(ex.InnerException);
    }

    [PqcFact]
    public void Malformed_json_header_is_wrapped_as_PqJwtValidationException()
    {
        using var signingKey = TestKeys.NewSigningKey();
        // Valid Base64, but the decoded header isn't valid JSON.
        var notJson = ToBase64Url(Encoding.UTF8.GetBytes("{not-json"));
        var payload = ToBase64Url(Encoding.UTF8.GetBytes("{}"));
        var sig = ToBase64Url(new byte[8]);
        var token = $"{notJson}.{payload}.{sig}";

        var ex = Assert.Throws<PqJwtValidationException>(
            () => Validator(signingKey, new FixedTimeProvider(Now)).Validate(token));
        // Inner is either JsonException OR an engine-wrapped subtype. Just
        // confirm the outer is the documented PqJwtValidationException.
        Assert.NotNull(ex);
    }

    private static string ToBase64Url(ReadOnlySpan<byte> data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string SignedTokenWithClaim(
        System.Security.Cryptography.MLDsa signingKey,
        TimeProvider clock,
        string claimName,
        object value)
    {
        var now = clock.GetUtcNow();
        var claims = new Dictionary<string, object>
        {
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(5).ToUnixTimeSeconds(),
            [claimName] = value,
        };
        var header = "{\"alg\":\"ML-DSA-65\",\"typ\":\"JWT\"}";
        var payload = JsonSerializer.Serialize(claims);
        var encodedHeader = ToBase64Url(Encoding.UTF8.GetBytes(header));
        var encodedPayload = ToBase64Url(Encoding.UTF8.GetBytes(payload));
        var signingInput = Encoding.ASCII.GetBytes($"{encodedHeader}.{encodedPayload}");
        var signature = ToBase64Url(signingKey.SignData(signingInput));
        return $"{encodedHeader}.{encodedPayload}.{signature}";
    }
}
