using System.Security.Cryptography;
using System.Text;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Internal;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// The executable security contract: the protocol-orchestration invariants of
/// <see cref="PqJwtValidator"/>, each pinned so a future refactor cannot silently
/// weaken it. These complement the per-behaviour tests elsewhere by locking the
/// <i>ordering</i> and <i>composition</i> guarantees that JWT libraries get wrong
/// far more often than the underlying cryptography.
/// <para>
/// Traceability to the normative spec (<c>docs/SPEC.md</c> → "Validation rules
/// (fail-closed, in order)") and the audit matrix in <c>CLAUDE.md</c>:
/// </para>
/// <list type="bullet">
/// <item>Steps 5→6: structural/`kid` checks precede the expensive ML-DSA verify.</item>
/// <item>Steps 6→7: the signature is verified before any payload claim is trusted.</item>
/// <item>Step 3: a 5-part token MUST decrypt to a 3-part signed JWT (no downgrade).</item>
/// </list>
/// </summary>
public sealed class SecurityInvariantsTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// SPEC step 5 before step 6: an unknown <c>kid</c> is rejected before the
    /// expensive ML-DSA verify runs. The token's signature is also broken — if
    /// verification ran first this would surface as <c>SignatureMismatch</c>;
    /// because it surfaces as <c>UnknownKeyId</c>, key resolution provably
    /// precedes signature verification (the cheap-check-first DoS guard).
    /// </summary>
    [PqcFact]
    public void Unknown_kid_is_rejected_before_the_signature_is_verified()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithKeyId("rotated-out-key")
            .WithSubject("subject")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();
        var tampered = TamperSignature(token);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureKeyResolver = _ => null },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(tampered));
        Assert.Equal(PqJwtFailureReason.UnknownKeyId, ex.Reason);
    }

    /// <summary>
    /// SPEC step 6 before step 7: the signature is verified before any claim is
    /// evaluated. The token is BOTH expired AND has a broken signature; the
    /// result is <c>SignatureMismatch</c>, never <c>Expired</c>. This locks the
    /// "never act on an unauthenticated payload claim" rule — if a future change
    /// moved the <c>exp</c> check ahead of verification (a recurring JWT-library
    /// mistake), this assertion flips to <c>Expired</c> and fails.
    /// </summary>
    [PqcFact]
    public void Signature_is_verified_before_claims_so_an_expired_forgery_reports_signature_mismatch()
    {
        using var signingKey = TestKeys.NewSigningKey();

        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithSubject("subject")
            .WithLifetime(TimeSpan.FromMinutes(1))
            .SignWith(signingKey)
            .Build();
        var tampered = TamperSignature(token);

        // Validate ten minutes after issue — well past the one-minute lifetime.
        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey) },
            new FixedTimeProvider(Now.AddMinutes(10)));

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(tampered));
        Assert.Equal(PqJwtFailureReason.SignatureMismatch, ex.Reason);
    }

    /// <summary>
    /// SPEC step 3 (no profile downgrade): a structurally valid, correctly
    /// AES-256-GCM-authenticated X-Wing envelope whose <i>plaintext is not a
    /// 3-part signed JWT</i> is rejected as <c>InnerNotSigned</c>. The GCM tag
    /// passes, so the only thing standing between this token and acceptance is
    /// the nested-profile guard — proving the validator cannot be tricked into
    /// treating arbitrary decrypted bytes as a verified payload.
    /// </summary>
    [PqcFact]
    public void Encrypted_envelope_whose_plaintext_is_not_a_signed_jwt_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();

        // The plaintext is deliberately NOT a 3-segment signed JWT.
        var token = EncryptArbitraryPlaintext(recipient.PublicKey, "this-is-not-a-jwt"u8);

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = recipient,
            ValidateLifetime = false,
        });

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Equal(PqJwtFailureReason.InnerNotSigned, ex.Reason);
    }

    /// <summary>
    /// The AES-GCM authentication tag and nonce lengths come from the v1 profile,
    /// not from the token. A 16-byte tag encodes to 22 base64url characters; the
    /// first 20 decode to a clean 15-byte (120-bit) prefix that AES-GCM would
    /// otherwise accept as a valid shorter tag. Honouring it would downgrade
    /// authentication strength and make the token malleable, so a tag that is not
    /// exactly 16 bytes is rejected. (Regression for a finding from PqJwtFuzzTests.)
    /// </summary>
    [PqcFact]
    public void Truncated_gcm_tag_is_rejected()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();

        var token = new PqJwtBuilder()
            .WithSubject("subject")
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        var parts = token.Split('.');
        parts[^1] = parts[^1][..20]; // 22 base64url chars (16 bytes) -> 20 (15 bytes)
        var truncated = string.Join('.', parts);

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
            DecryptionKey = recipient,
            ValidateLifetime = false,
        });

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(truncated));
        Assert.Equal(PqJwtFailureReason.DecryptionFailed, ex.Reason);
    }

    // Flips the last character of the signature segment so the ML-DSA signature
    // no longer verifies, without disturbing header or payload.
    private static string TamperSignature(string token)
    {
        var parts = token.Split('.');
        parts[^1] = parts[^1][..^1] + (parts[^1][^1] == 'A' ? 'B' : 'A');
        return string.Join('.', parts);
    }

    // Produces a well-formed 5-part X-Wing/A256GCM token (correct header, real
    // KEM ciphertext, valid GCM tag over the header-as-AAD) wrapping an arbitrary
    // plaintext. Mirrors PqJwtBuilder's encryption path via the internal engine
    // (reachable through InternalsVisibleTo) so the envelope authenticates
    // cleanly and only the inner-content check can reject it.
    private static string EncryptArbitraryPlaintext(XWingPublicKey recipient, ReadOnlySpan<byte> plaintext)
    {
        var header =
            $$"""{"alg":"{{PqJwtAlgorithms.XWing}}","enc":"{{PqJwtAlgorithms.Aes256Gcm}}","typ":"{{PqJwtAlgorithms.TokenType}}","cty":"{{PqJwtAlgorithms.TokenType}}"}""";
        var encodedHeader = Base64Url.EncodeUtf8(header);

        var (sharedSecret, kemCiphertext) = XWing.Encapsulate(recipient);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            using (var gcm = new AesGcm(sharedSecret, tag.Length))
            {
                gcm.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.ASCII.GetBytes(encodedHeader));
            }

            return string.Join('.',
                encodedHeader,
                Base64Url.Encode(kemCiphertext),
                Base64Url.Encode(nonce),
                Base64Url.Encode(ciphertext),
                Base64Url.Encode(tag));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}
