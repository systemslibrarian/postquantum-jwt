using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Locks the <see cref="PqJwtValidationException.Reason"/> emitted at every throw
/// site. This is the safety net that makes the metrics <c>reason</c> tag a typed,
/// compiler-checked value instead of a string parsed out of a message: if a throw
/// site is given the wrong (or no) reason, one of these tests fails.
/// </summary>
public sealed class PqJwtFailureReasonTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    // ── helpers ──────────────────────────────────────────────────────────

    private static string B64(string s) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(s));

    private static string SignedHeader() => $"{{\"alg\":\"{PqJwtAlgorithms.MLDsa65}\",\"typ\":\"JWT\"}}";

    // A validator whose resolver returns the given key (or null). Constructing it
    // needs no crypto when key is null — useful for the pre-signature throw sites.
    private static PqJwtValidator ResolverValidator(MLDsa? key) =>
        new(new PqJwtValidationParameters { SignatureKeyResolver = _ => key });

    // Craft and genuinely sign a token over arbitrary header/payload JSON, so the
    // post-signature throw sites (claims parsing/validation) are reachable.
    private static string SignCrafted(MLDsa key, string headerJson, string payloadJson)
    {
        var h = B64(headerJson);
        var p = B64(payloadJson);
        var sig = key.SignData(Encoding.ASCII.GetBytes($"{h}.{p}"));
        return $"{h}.{p}.{Base64Url.EncodeToString(sig)}";
    }

    private static string TamperHeader(string token, Action<JsonObject> mutate)
    {
        var parts = token.Split('.');
        var header = JsonNode.Parse(Encoding.UTF8.GetString(Base64Url.DecodeFromChars(parts[0])))!.AsObject();
        mutate(header);
        parts[0] = B64(header.ToJsonString());
        return string.Join('.', parts);
    }

    private static PqJwtFailureReason ReasonOf(Func<PqJwtValidationResult> act)
    {
        var ex = Assert.Throws<PqJwtValidationException>(act);
        return ex.Reason;
    }

    // ── pre-signature throw sites (no crypto required) ─────────────────────

    [Fact]
    public void Wrong_segment_count_reports_MalformedToken()
    {
        var reason = ReasonOf(() => ResolverValidator(null).Validate("a.b.c.d"));
        Assert.Equal(PqJwtFailureReason.MalformedToken, reason);
    }

    [Fact]
    public void Non_base64url_header_reports_MalformedEncoding()
    {
        var reason = ReasonOf(() => ResolverValidator(null).Validate("@@@.payload.sig"));
        Assert.Equal(PqJwtFailureReason.MalformedEncoding, reason);
    }

    [Fact]
    public void Header_that_is_not_json_reports_MalformedJson()
    {
        var reason = ReasonOf(() => ResolverValidator(null).Validate($"{B64("not json")}.{B64("{}")}.sig"));
        Assert.Equal(PqJwtFailureReason.MalformedJson, reason);
    }

    // Regression: Tier 2 coverage-guided fuzzing (SharpFuzz + libFuzzer) produced a
    // 5-segment "encrypted" token whose header JSON had duplicate "enc"/"typ"/"cty"
    // members. JsonNode.Parse accepted it (lazy), but the first indexer access in
    // JoseHeader.Parse triggered JsonObject.InitializeDictionary → ArgumentException,
    // which slipped past the JsonException catch and escaped Validate as an unsealed
    // exception type. The fix wraps that path; this test pins the closed reason.
    [Fact]
    public void Header_with_duplicate_keys_reports_MalformedJson()
    {
        const string duplicates = "{\"alg\":\"ML-DSA-65\",\"typ\":\"JWT\",\"typ\":\"JWT\"}";
        var reason = ReasonOf(() => ResolverValidator(null).Validate($"{B64(duplicates)}.{B64("{}")}.sig"));
        Assert.Equal(PqJwtFailureReason.MalformedJson, reason);
    }

    [Fact]
    public void Wrong_signature_algorithm_reports_AlgorithmNotAccepted()
    {
        var token = $"{B64("{\"alg\":\"none\"}")}.{B64("{}")}.sig";
        var reason = ReasonOf(() => ResolverValidator(null).Validate(token));
        Assert.Equal(PqJwtFailureReason.AlgorithmNotAccepted, reason);
    }

    [Fact]
    public void Unresolved_kid_reports_UnknownKeyId()
    {
        // Resolver returns null -> fail closed before any signature work.
        var token = $"{B64($"{{\"alg\":\"{PqJwtAlgorithms.MLDsa65}\",\"kid\":\"missing\"}}")}.{B64("{}")}.sig";
        var reason = ReasonOf(() => ResolverValidator(null).Validate(token));
        Assert.Equal(PqJwtFailureReason.UnknownKeyId, reason);
    }

    // ── signed-path throw sites (require crypto) ───────────────────────────

    [PqcFact]
    public void Malformed_signature_encoding_reports_SignatureMalformed()
    {
        using var key = TestKeys.NewSigningKey();
        var token = $"{B64(SignedHeader())}.{B64("{}")}.@@@";
        var reason = ReasonOf(() => ResolverValidator(key).Validate(token));
        Assert.Equal(PqJwtFailureReason.SignatureMalformed, reason);
    }

    [PqcFact]
    public void Bad_signature_reports_SignatureMismatch()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        using var attacker = TestKeys.NewSigningKey();
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(attacker).Build();
        var reason = ReasonOf(() => ResolverValidator(verify).Validate(token));
        Assert.Equal(PqJwtFailureReason.SignatureMismatch, reason);
    }

    [PqcFact]
    public void Payload_that_is_not_a_json_object_reports_MalformedPayload()
    {
        using var key = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(key);
        var token = SignCrafted(key, SignedHeader(), "123"); // valid JSON, not an object
        var reason = ReasonOf(() => ResolverValidator(verify).Validate(token));
        Assert.Equal(PqJwtFailureReason.MalformedPayload, reason);
    }

    [PqcFact]
    public void Expired_token_reports_Expired()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        var token = new PqJwtBuilder(new FixedTimeProvider(Now.AddHours(-2)))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(signing).Build();
        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = verify },
            new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.Expired, ReasonOf(() => validator.Validate(token)));
    }

    [PqcFact]
    public void Not_yet_valid_token_reports_NotYetValid()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithNotBefore(Now.AddMinutes(30)).WithLifetime(TimeSpan.FromHours(1))
            .SignWith(signing).Build();
        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = verify },
            new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.NotYetValid, ReasonOf(() => validator.Validate(token)));
    }

    [PqcFact]
    public void Missing_exp_when_required_reports_MissingExpiration()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        // Build with no lifetime so there is no exp claim.
        var token = new PqJwtBuilder(new FixedTimeProvider(Now)).SignWith(signing).Build();
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            RequireExpiration = true,
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.MissingExpiration, ReasonOf(() => validator.Validate(token)));
    }

    [PqcFact]
    public void Wrong_issuer_reports_IssuerMismatch()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithIssuer("https://evil.example").WithLifetime(TimeSpan.FromMinutes(10))
            .SignWith(signing).Build();
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            ValidIssuer = "https://issuer.example",
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.IssuerMismatch, ReasonOf(() => validator.Validate(token)));
    }

    [PqcFact]
    public void Wrong_audience_reports_AudienceMismatch()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithAudience("https://other.example").WithLifetime(TimeSpan.FromMinutes(10))
            .SignWith(signing).Build();
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            ValidAudience = "https://api.example",
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.AudienceMismatch, ReasonOf(() => validator.Validate(token)));
    }

    [PqcFact]
    public void Replay_without_jti_reports_MissingJwtId()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(signing).Build();
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            ReplayCache = new InMemoryReplayCache(),
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.MissingJwtId, ReasonOf(() => validator.Validate(token)));
    }

    [PqcFact]
    public void Second_use_of_a_jti_reports_ReplayDetected()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithJwtId("jti-1").WithLifetime(TimeSpan.FromMinutes(10)).SignWith(signing).Build();
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            // Same fixed clock as the token so the cache doesn't prune the entry
            // as "expired" between the two validations.
            ReplayCache = new InMemoryReplayCache(new FixedTimeProvider(Now)),
        }, new FixedTimeProvider(Now));
        validator.Validate(token); // first use succeeds
        Assert.Equal(PqJwtFailureReason.ReplayDetected, ReasonOf(() => validator.Validate(token)));
    }

    [Fact]
    public void Control_characters_in_alg_are_sanitized_out_of_the_message()
    {
        // Regression: a CRLF in an attacker-controlled header value must not appear
        // verbatim in the exception message (which a consumer may log) — that would
        // be a log-injection / log-forging vector.
        var token = $"{B64("{\"alg\":\"none\\r\\nInjected-Log-Line: evil\"}")}.{B64("{}")}.sig";
        var ex = Assert.Throws<PqJwtValidationException>(() => ResolverValidator(null).Validate(token));
        Assert.Equal(PqJwtFailureReason.AlgorithmNotAccepted, ex.Reason);
        Assert.DoesNotContain('\n', ex.Message);
        Assert.DoesNotContain('\r', ex.Message);
    }

    [Fact]
    public void Control_characters_in_kid_are_sanitized_out_of_the_message()
    {
        var token = $"{B64($"{{\"alg\":\"{PqJwtAlgorithms.MLDsa65}\",\"kid\":\"k\\r\\nevil\"}}")}.{B64("{}")}.sig";
        var ex = Assert.Throws<PqJwtValidationException>(() => ResolverValidator(null).Validate(token));
        Assert.Equal(PqJwtFailureReason.UnknownKeyId, ex.Reason);
        Assert.DoesNotContain('\n', ex.Message);
        Assert.DoesNotContain('\r', ex.Message);
    }

    [Fact]
    public void An_absurdly_long_token_is_rejected_before_parsing()
    {
        // Reject oversized input up front (no split/decode/verify), capping
        // pre-verification work on a memory/CPU-exhaustion attempt.
        var huge = new string('a', 200_000);
        Assert.Equal(PqJwtFailureReason.MalformedToken,
            ReasonOf(() => ResolverValidator(null).Validate(huge)));
    }

    // ── malformed header/claim hardening (no InvalidOperationException escape) ──

    [Theory]
    [InlineData("{\"alg\":123}")]            // number
    [InlineData("{\"alg\":[\"none\"]}")]     // array
    [InlineData("{\"alg\":true}")]           // bool
    [InlineData("{\"alg\":{\"x\":1}}")]      // object
    public void Non_string_alg_is_rejected_not_crashed(string headerJson)
    {
        // Regression: a present-but-non-string header field must NOT escape as an
        // uncaught InvalidOperationException (HTTP 500); it fails closed as
        // PqJwtValidationException. ReasonOf asserts the exception type.
        var token = $"{B64(headerJson)}.{B64("{}")}.sig";
        Assert.Equal(PqJwtFailureReason.InvalidHeader,
            ReasonOf(() => ResolverValidator(null).Validate(token)));
    }

    [PqcTheory]
    [InlineData("{\"exp\":1700000000.5}")]    // fractional number
    [InlineData("{\"exp\":\"1700000000\"}")]  // string
    [InlineData("{\"exp\":[1700000000]}")]    // array
    [InlineData("{\"exp\":99999999999999}")]  // integer beyond DateTimeOffset range
    public void Malformed_exp_claim_is_rejected(string payloadJson)
    {
        // Regression: a present-but-malformed exp must be rejected, not silently
        // ignored (immortal token) — and an out-of-range integer must not throw
        // ArgumentOutOfRangeException out of the validator (a 500).
        using var key = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(key);
        var token = SignCrafted(key, SignedHeader(), payloadJson);
        Assert.Equal(PqJwtFailureReason.MalformedTimeClaim,
            ReasonOf(() => ResolverValidator(verify).Validate(token)));
    }

    [PqcFact]
    public void Out_of_range_exp_is_safe_to_read_on_a_result_when_lifetime_checks_are_off()
    {
        // With ValidateLifetime off the token is accepted; reading result.ExpiresAt
        // must return null, never throw, even for an out-of-range exp.
        using var key = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(key);
        var token = SignCrafted(key, SignedHeader(), "{\"sub\":\"x\",\"exp\":99999999999999}");
        var result = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            ValidateLifetime = false,
        }).Validate(token);

        Assert.Null(result.ExpiresAt);   // safe, not an exception
        Assert.Equal("x", result.Subject);
    }

    [PqcFact]
    public void Replay_protection_requires_an_exp_claim()
    {
        // A replay-protected token with no exp would create a never-expiring cache
        // entry; require exp so the entry can be pruned.
        using var key = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(key);
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithJwtId("jti-no-exp").SignWith(key).Build(); // no WithLifetime -> no exp
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            ReplayCache = new InMemoryReplayCache(new FixedTimeProvider(Now)),
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.MissingExpiration,
            ReasonOf(() => validator.Validate(token)));
    }

    [PqcFact]
    public void Malformed_nbf_claim_is_rejected()
    {
        // exp is far in the future so we reach the nbf check; nbf is malformed.
        using var key = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(key);
        var token = SignCrafted(key, SignedHeader(), "{\"exp\":4102444800,\"nbf\":\"soon\"}");
        Assert.Equal(PqJwtFailureReason.MalformedTimeClaim,
            ReasonOf(() => ResolverValidator(verify).Validate(token)));
    }

    // ── encrypted-path throw sites (require crypto) ────────────────────────

    [PqcFact]
    public void Tampered_enc_header_reports_AlgorithmNotAccepted()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        using var recipient = XWingPrivateKey.Generate();
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(signing)
            .EncryptFor(recipient.PublicKey).Build();

        // Header checks fire before decryption, so a bad enc is caught up front.
        var tampered = TamperHeader(token, h => h["enc"] = "BOGUS-ENC");
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            DecryptionKey = recipient,
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.AlgorithmNotAccepted, ReasonOf(() => validator.Validate(tampered)));
    }

    [PqcFact]
    public void Tampered_cty_header_reports_InvalidHeader()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        using var recipient = XWingPrivateKey.Generate();
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(signing)
            .EncryptFor(recipient.PublicKey).Build();

        var tampered = TamperHeader(token, h => h["cty"] = "NOT-JWT");
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            DecryptionKey = recipient,
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.InvalidHeader, ReasonOf(() => validator.Validate(tampered)));
    }

    [PqcFact]
    public void Corrupted_key_agreement_segment_reports_KeyAgreementMalformed()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        using var recipient = XWingPrivateKey.Generate();
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(signing)
            .EncryptFor(recipient.PublicKey).Build();

        var parts = token.Split('.');
        parts[1] = "@@@"; // not valid base64url -> decapsulation input is malformed
        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            DecryptionKey = recipient,
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.KeyAgreementMalformed,
            ReasonOf(() => validator.Validate(string.Join('.', parts))));
    }

    [PqcFact]
    public void Wrong_recipient_key_reports_DecryptionFailed()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        using var recipient = XWingPrivateKey.Generate();
        using var wrongRecipient = XWingPrivateKey.Generate();
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(signing)
            .EncryptFor(recipient.PublicKey).Build();

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            DecryptionKey = wrongRecipient,
        }, new FixedTimeProvider(Now));
        Assert.Equal(PqJwtFailureReason.DecryptionFailed, ReasonOf(() => validator.Validate(token)));
    }
}
