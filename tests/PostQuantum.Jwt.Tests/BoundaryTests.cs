using System.Security.Cryptography;
using System.Text;
using PostQuantum.Jwt.Internal;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Boundary-condition tests added in response to Stryker.NET mutation testing
/// (see <c>stryker-config.json</c> and <c>docs/TESTING.md</c>): each of these
/// tests targets a specific equality-operator mutation that survived the
/// initial mutation run on <c>PqJwtValidator</c>, where the on-disk operator
/// (e.g. <c>&gt;</c>) and its mutated form (<c>&gt;=</c>) only differ at exactly
/// one input value. A passing test here corresponds to a killed mutant.
/// </summary>
public sealed class BoundaryTests
{
    private const int MaxTokenLength = 128 * 1024;
    private const long UnixSecondsMax = 253402300799L;
    private const long UnixSecondsMin = -62135596800L;

    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(60);

    private static string B64(string s) => Base64Url.EncodeUtf8(s);

    private static string SignCrafted(MLDsa key, string headerJson, string payloadJson)
    {
        var h = B64(headerJson);
        var p = B64(payloadJson);
        var sig = key.SignData(Encoding.ASCII.GetBytes($"{h}.{p}"));
        return $"{h}.{p}.{Base64Url.Encode(sig)}";
    }

    private static string SignedHeader() => $"{{\"alg\":\"{PqJwtAlgorithms.MLDsa65}\",\"typ\":\"JWT\"}}";

    // ── token length boundary (PqJwtValidator.cs line 113: token.Length > MaxTokenLength) ──

    /// <summary>
    /// A token whose length is *exactly* <c>MaxTokenLength</c> (128 KiB) must NOT
    /// be rejected by the pre-parse length cap — the cap is documented as
    /// <c>&gt;</c>, not <c>&gt;=</c>. Stryker mutated this to <c>&gt;=</c>, which
    /// would reject at-cap tokens too. We don't care which other reason the
    /// validator surfaces (the crafted token won't verify anyway); we care that
    /// it isn't <c>MalformedToken</c>.
    /// </summary>
    [Fact]
    public void Token_at_max_length_is_not_rejected_for_length()
    {
        var token = TokenOfLength(MaxTokenLength);
        Assert.Equal(MaxTokenLength, token.Length);

        var validator = new PqJwtValidator(new PqJwtValidationParameters { SignatureKeyResolver = _ => null });
        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.NotEqual(PqJwtFailureReason.MalformedToken, ex.Reason);
    }

    /// <summary>
    /// One byte past the cap: this is the existing-behaviour side of the
    /// boundary — the validator must reject with <c>MalformedToken</c>.
    /// </summary>
    [Fact]
    public void Token_one_byte_past_max_length_is_MalformedToken()
    {
        var token = TokenOfLength(MaxTokenLength + 1);
        Assert.Equal(MaxTokenLength + 1, token.Length);

        var validator = new PqJwtValidator(new PqJwtValidationParameters { SignatureKeyResolver = _ => null });
        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Equal(PqJwtFailureReason.MalformedToken, ex.Reason);
    }

    // ── exp boundary (PqJwtValidator.cs line 432: now > exp + skew) ──

    /// <summary>
    /// <c>exp == now - skew</c> means <c>exp + skew == now</c>; the current code
    /// rejects only when <c>now &gt; exp + skew</c>, so this exactly-on-the-edge
    /// token must validate. Stryker mutated <c>&gt;</c> to <c>&gt;=</c>, which
    /// would reject at-the-edge tokens.
    /// </summary>
    [PqcFact]
    public void Exp_exactly_at_skew_boundary_is_accepted()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var exp = Now - Skew; // now - skew, so exp + skew == now
        var payload = $"{{\"sub\":\"s\",\"exp\":{exp.ToUnixTimeSeconds()}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                ClockSkew = Skew,
            },
            clock);

        var result = validator.Validate(token);
        Assert.NotNull(result);
    }

    /// <summary>
    /// One second past the skew boundary: <c>now &gt; exp + skew</c> is true,
    /// so the token must be rejected as <c>Expired</c>.
    /// </summary>
    [PqcFact]
    public void Exp_one_second_past_skew_boundary_is_Expired()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var exp = Now - Skew - TimeSpan.FromSeconds(1);
        var payload = $"{{\"sub\":\"s\",\"exp\":{exp.ToUnixTimeSeconds()}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                ClockSkew = Skew,
            },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Equal(PqJwtFailureReason.Expired, ex.Reason);
    }

    // ── nbf boundary (PqJwtValidator.cs line 455: now < nbf - skew) ──

    /// <summary>
    /// <c>nbf == now + skew</c> means <c>nbf - skew == now</c>; the current code
    /// rejects only when <c>now &lt; nbf - skew</c>, so this exactly-on-the-edge
    /// token must validate. Stryker mutated <c>&lt;</c> to <c>&lt;=</c>.
    /// </summary>
    [PqcFact]
    public void Nbf_exactly_at_skew_boundary_is_accepted()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var nbf = Now + Skew; // nbf - skew == now
        var exp = Now + TimeSpan.FromHours(1);
        var payload = $"{{\"sub\":\"s\",\"nbf\":{nbf.ToUnixTimeSeconds()},\"exp\":{exp.ToUnixTimeSeconds()}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                ClockSkew = Skew,
            },
            clock);

        var result = validator.Validate(token);
        Assert.NotNull(result);
    }

    /// <summary>
    /// One second further into the future: <c>now &lt; nbf - skew</c> is true,
    /// so <c>NotYetValid</c>.
    /// </summary>
    [PqcFact]
    public void Nbf_one_second_past_skew_boundary_is_NotYetValid()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var nbf = Now + Skew + TimeSpan.FromSeconds(1);
        var exp = Now + TimeSpan.FromHours(1);
        var payload = $"{{\"sub\":\"s\",\"nbf\":{nbf.ToUnixTimeSeconds()},\"exp\":{exp.ToUnixTimeSeconds()}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                ClockSkew = Skew,
            },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Equal(PqJwtFailureReason.NotYetValid, ex.Reason);
    }

    // ── Unix-seconds range (PqJwtValidator.cs line 551: seconds is >= Min and <= Max) ──

    /// <summary>
    /// <c>exp == UnixSecondsMax</c> is the highest value <c>DateTimeOffset</c>
    /// can represent. The parser uses an inclusive upper bound (<c>&lt;= Max</c>),
    /// so the token must parse and validate. Stryker mutated <c>&lt;= Max</c>
    /// to <c>&lt; Max</c>, which would reject at-cap times as <c>MalformedTimeClaim</c>.
    /// </summary>
    [PqcFact]
    public void Exp_at_max_Unix_seconds_is_accepted()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var payload = $"{{\"sub\":\"s\",\"exp\":{UnixSecondsMax}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey) },
            clock);

        var result = validator.Validate(token);
        Assert.NotNull(result);
    }

    /// <summary>
    /// One above the cap: the parser must reject as <c>MalformedTimeClaim</c>
    /// rather than passing the value to <c>DateTimeOffset.FromUnixTimeSeconds</c>
    /// (which would throw <c>ArgumentOutOfRangeException</c> outside the
    /// validator's caught set).
    /// </summary>
    [PqcFact]
    public void Exp_above_max_Unix_seconds_is_MalformedTimeClaim()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var payload = $"{{\"sub\":\"s\",\"exp\":{UnixSecondsMax + 1}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey) },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Equal(PqJwtFailureReason.MalformedTimeClaim, ex.Reason);
    }

    /// <summary>
    /// <c>exp == UnixSecondsMin</c> is the lowest value the inclusive lower
    /// bound accepts; the token parses, then rejects as <c>Expired</c> (far in
    /// the past) rather than <c>MalformedTimeClaim</c>. Stryker mutated
    /// <c>&gt;= Min</c> to <c>&gt; Min</c>, which would surface
    /// <c>MalformedTimeClaim</c> at the boundary.
    /// </summary>
    [PqcFact]
    public void Exp_at_min_Unix_seconds_is_Expired_not_MalformedTimeClaim()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var payload = $"{{\"sub\":\"s\",\"exp\":{UnixSecondsMin}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey) },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Equal(PqJwtFailureReason.Expired, ex.Reason);
    }

    /// <summary>
    /// Symmetric to <see cref="Exp_at_max_Unix_seconds_is_accepted"/>: an
    /// <c>nbf</c> at <c>UnixSecondsMin</c> means the not-yet-valid window
    /// closed at the start of representable time, so the lifetime check
    /// must pass. Without the matching underflow guard at
    /// <c>nbf - skew</c>, this would escape as
    /// <see cref="ArgumentOutOfRangeException"/>.
    /// </summary>
    [PqcFact]
    public void Nbf_at_min_Unix_seconds_is_accepted()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var exp = Now + TimeSpan.FromHours(1);
        var payload = $"{{\"sub\":\"s\",\"nbf\":{UnixSecondsMin},\"exp\":{exp.ToUnixTimeSeconds()}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                ClockSkew = Skew,
            },
            clock);

        var result = validator.Validate(token);
        Assert.NotNull(result);
    }

    /// <summary>
    /// <c>nbf</c> at <c>UnixSecondsMax</c>: token claims it isn't valid until the
    /// end of representable time, so for any realistic <c>now</c> it must be
    /// rejected as <c>NotYetValid</c> — *not* leak the underlying arithmetic.
    /// </summary>
    [PqcFact]
    public void Nbf_at_max_Unix_seconds_is_NotYetValid()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var payload = $"{{\"sub\":\"s\",\"nbf\":{UnixSecondsMax},\"exp\":{UnixSecondsMax}}}";
        var token = SignCrafted(signingKey, SignedHeader(), payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                ClockSkew = Skew,
            },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Equal(PqJwtFailureReason.NotYetValid, ex.Reason);
    }

    // ── helpers ──

    // Builds a structurally-valid 3-part token (header.payload.signature) whose
    // total UTF-8/ASCII length is exactly `length`. The signature segment is
    // padding base64url characters — meaningless to ML-DSA verification, which
    // is fine: these tests target the pre-parse length check, not signature
    // verification. The validator's later rejection (UnknownKeyId or
    // SignatureMalformed) is the expected non-length-related failure.
    private static string TokenOfLength(int length)
    {
        var header = B64(SignedHeader());
        var payload = B64("{}");
        var fixedPart = header + "." + payload + ".";
        var pad = length - fixedPart.Length;
        if (pad < 0)
        {
            throw new ArgumentException("length is shorter than the minimum token frame.", nameof(length));
        }

        return fixedPart + new string('A', pad);
    }
}
