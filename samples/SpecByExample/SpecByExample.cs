// PostQuantum.Jwt — Spec by Example
//
// An executable specification. Each test name is a lesson about how the library
// behaves; the body is the smallest code that proves it. Set a breakpoint in any
// test and step through it to watch the mechanics — especially the Attack-Mode
// cases, where you can see a tampered token fail signature verification line by
// line, in your own IDE, without a console menu.
//
// These tests skip themselves on hosts without native ML-KEM/ML-DSA support
// (OpenSSL 3.5+ or recent Windows) rather than failing spuriously.
//
// To God be the glory — 1 Corinthians 10:31.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PostQuantum.Jwt;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.SpecByExample;

/// <summary>Skips a fact when the runtime lacks native ML-DSA/ML-KEM support.</summary>
public sealed class RequiresPqAttribute : FactAttribute
{
    public RequiresPqAttribute()
    {
        if (!MLDsa.IsSupported)
            Skip = "Native ML-DSA/ML-KEM not available (needs OpenSSL 3.5+ or recent Windows).";
    }
}

public sealed class HappyPath : IDisposable
{
    private readonly MLDsa _signing = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    private readonly MLDsa _verify;

    public HappyPath() =>
        _verify = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, _signing.ExportMLDsaPublicKey());

    [RequiresPq]
    public void A_signed_token_round_trips_and_exposes_its_claims()
    {
        string token = new PqJwtBuilder()
            .WithIssuer("https://issuer.example")
            .WithSubject("user-123")
            .WithAudience("https://api.example")
            .WithLifetime(TimeSpan.FromMinutes(10))
            .WithClaim("role", "reader")
            .SignWith(_signing)
            .Build();

        var result = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verify,
            ValidIssuer = "https://issuer.example",
            ValidAudience = "https://api.example",
        }).Validate(token);   // fail-closed: returns ONLY on success

        Assert.Equal("user-123", result.Subject);
        Assert.Equal("reader", result.GetString("role"));
        Assert.False(result.WasEncrypted);
    }

    [RequiresPq]
    public void A_sign_then_encrypt_token_is_confidential_and_validates_with_the_recipient_key()
    {
        using var recipient = XWingPrivateKey.Generate();

        string token = new PqJwtBuilder()
            .WithSubject("confidential")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(_signing)
            .EncryptFor(recipient.PublicKey)
            .Build();

        // 5 segments = JWE-style encrypted form.
        Assert.Equal(5, token.Split('.').Length);

        var result = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verify,
            DecryptionKey = recipient,
        }).Validate(token);

        Assert.True(result.WasEncrypted);
        Assert.Equal("confidential", result.Subject);
    }

    public void Dispose() { _signing.Dispose(); _verify.Dispose(); }
}

public sealed class AttackMode : IDisposable
{
    private readonly MLDsa _signing = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    private readonly MLDsa _verify;
    private readonly PqJwtValidator _validator;

    public AttackMode()
    {
        _verify = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, _signing.ExportMLDsaPublicKey());
        _validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verify,
        });
    }

    private string CapturedReaderToken() => new PqJwtBuilder()
        .WithSubject("alice")
        .WithLifetime(TimeSpan.FromMinutes(15))
        .WithClaim("role", "reader")
        .SignWith(_signing)
        .Build();

    [RequiresPq]
    public void Editing_a_claim_and_reusing_the_signature_breaks_verification()
    {
        // The realistic forgery: decode payload, escalate role to admin,
        // re-encode, keep the captured signature. Breakpoint here and step in.
        string tampered = EscalateRole(CapturedReaderToken());

        var ex = Assert.Throws<PqJwtValidationException>(() => _validator.Validate(tampered));
        Assert.Contains("signature", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [RequiresPq]
    public void An_alg_none_token_is_rejected()
    {
        string forged = ForgeAlgNone(CapturedReaderToken());
        Assert.Throws<PqJwtValidationException>(() => _validator.Validate(forged));
    }

    [RequiresPq]
    public void A_token_signed_by_the_wrong_key_is_rejected()
    {
        using var attacker = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        string forged = new PqJwtBuilder()
            .WithSubject("alice").WithClaim("role", "admin")
            .WithLifetime(TimeSpan.FromMinutes(15)).SignWith(attacker).Build();

        Assert.Throws<PqJwtValidationException>(() => _validator.Validate(forged));
    }

    [RequiresPq]
    public void An_expired_token_is_rejected()
    {
        string expired = new PqJwtBuilder()
            .WithSubject("alice")
            .WithExpiration(DateTimeOffset.UtcNow.AddMinutes(-10))
            .WithNotBefore(DateTimeOffset.UtcNow.AddMinutes(-20))
            .SignWith(_signing).Build();

        Assert.Throws<PqJwtValidationException>(() => _validator.Validate(expired));
    }

    [RequiresPq]
    public void A_token_with_no_exp_is_rejected()
    {
        string noExp = new PqJwtBuilder()
            .WithSubject("alice").WithClaim("role", "reader")
            .SignWith(_signing).Build();

        Assert.Throws<PqJwtValidationException>(() => _validator.Validate(noExp));
    }

    [RequiresPq]
    public void The_same_one_time_token_cannot_be_used_twice()
    {
        var replayValidator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verify,
            ReplayCache = new InMemoryReplayCache(),
            RequireReplayProtection = true,
        });

        string token = new PqJwtBuilder()
            .WithSubject("alice").WithLifetime(TimeSpan.FromMinutes(5))
            .WithJwtId(Guid.NewGuid().ToString("N")).SignWith(_signing).Build();

        replayValidator.Validate(token);   // first use: accepted
        Assert.Throws<PqJwtValidationException>(() => replayValidator.Validate(token)); // second: replay
    }

    // --- helpers (educational tampering only) ---

    private static string EscalateRole(string token)
    {
        var parts = token.Split('.');
        string payloadJson = Decode(parts[1]);
        using var doc = JsonDocument.Parse(payloadJson);
        var dict = new Dictionary<string, JsonElement>();
        foreach (var p in doc.RootElement.EnumerateObject()) dict[p.Name] = p.Value.Clone();
        using var admin = JsonDocument.Parse("\"admin\"");
        dict["role"] = admin.RootElement.Clone();
        parts[1] = Encode(JsonSerializer.Serialize(dict));   // signature (parts[2]) untouched
        return string.Join('.', parts);
    }

    private static string ForgeAlgNone(string token)
    {
        var parts = token.Split('.');
        parts[0] = Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        return parts[0] + "." + parts[1] + ".";
    }

    private static string Decode(string seg)
    {
        string s = seg.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return Encoding.UTF8.GetString(Convert.FromBase64String(s));
    }

    private static string Encode(string text) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(text)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public void Dispose() { _signing.Dispose(); _verify.Dispose(); }
}
