using FsCheck;
using FsCheck.Xunit;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Internal;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Property-based tests: instead of asserting on hand-picked inputs, FsCheck
/// generates random inputs and checks that the invariant holds for all of them.
/// These tests sit on top of the deterministic suite — they don't replace the
/// fail-closed locks, they widen the search for inputs we didn't think of.
/// </summary>
public sealed class PqJwtPropertyTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// Base64Url encode/decode must be involutive across arbitrary byte arrays —
    /// any byte sequence we put in must come back identical.
    /// </summary>
    [Property(MaxTest = 200)]
    public bool Base64Url_round_trip_is_involutive(byte[] input)
    {
        input ??= [];
        var encoded = Base64Url.Encode(input);
        var decoded = Base64Url.Decode(encoded);
        return decoded.SequenceEqual(input);
    }

    /// <summary>
    /// Base64Url encoded output is always URL-safe: no '+', '/', '=' anywhere.
    /// </summary>
    [Property(MaxTest = 200)]
    public bool Base64Url_encoded_output_is_URL_safe(byte[] input)
    {
        input ??= [];
        var encoded = Base64Url.Encode(input);
        return !encoded.Contains('+') && !encoded.Contains('/') && !encoded.Contains('=');
    }

    /// <summary>
    /// For any non-empty token round-tripped through builder → validator,
    /// every custom string claim must come back exactly as it went in.
    /// </summary>
    [PqcProperty(MaxTest = 25)]
    public bool Signed_tokens_round_trip_arbitrary_string_claims(NonEmptyString name, NonNull<string> value)
    {
        // FsCheck generates arbitrary names; avoid reserved top-level claims.
        var claimName = name.Get;
        if (claimName is "iss" or "sub" or "aud" or "exp" or "nbf" or "iat" or "jti")
        {
            return true;
        }

        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .WithClaim(claimName, value.Get)
            .SignWith(signingKey)
            .Build();

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
        }, clock);

        var result = validator.Validate(token);
        return result.GetString(claimName) == value.Get;
    }

    /// <summary>
    /// For any signed token, flipping a single byte anywhere in the signature
    /// segment must cause validation to fail. The post-quantum counterpart to
    /// "the signature actually covers what we claim it covers".
    /// </summary>
    [PqcProperty(MaxTest = 20)]
    public bool Flipping_any_byte_in_the_signature_invalidates_the_token(PositiveInt flipPosition)
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("subject")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var parts = token.Split('.');
        var sigBytes = Base64Url.Decode(parts[2]);
        var index = flipPosition.Get % sigBytes.Length;
        sigBytes[index] ^= 0x01;
        var tampered = $"{parts[0]}.{parts[1]}.{Base64Url.Encode(sigBytes)}";

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
        }, clock);

        try
        {
            validator.Validate(tampered);
            return false;
        }
        catch (PqJwtValidationException)
        {
            return true;
        }
    }

    /// <summary>
    /// X-Wing encapsulate-then-decapsulate matches across many freshly generated
    /// key pairs.
    /// </summary>
    [PqcProperty(MaxTest = 15)]
    public bool X_Wing_encapsulate_decapsulate_round_trips()
    {
        using var recipient = XWingPrivateKey.Generate();
        var (senderSecret, ciphertext) = XWing.Encapsulate(recipient.PublicKey);
        var recipientSecret = XWing.Decapsulate(recipient, ciphertext);
        return senderSecret.SequenceEqual(recipientSecret);
    }
}
