using System.Security.Cryptography;
using System.Text;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Internal;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// The named red-team scenarios: structural attacks a JWT/JWE library has to
/// defend against, each with the attack story in its docstring. This file
/// complements (and cross-references) the per-throw-site tests in
/// <c>PqJwtFailureReasonTests</c>, the orchestration invariants in
/// <c>SecurityInvariantsTests</c>, the Stryker-driven boundary cases in
/// <c>BoundaryTests</c>, and the FsCheck adversarial sweep in
/// <c>PqJwtFuzzTests</c>. It is a discoverability layer for reviewers asking
/// "do they defend against attack X?" — each test name is a sentence stating
/// the attack and the defense.
/// <para>
/// Attack categories *already* covered elsewhere (not duplicated here):
/// </para>
/// <list type="bullet">
/// <item>Algorithm confusion (<c>alg: none</c>, wrong alg) — <c>PqJwtFailureReasonTests.Wrong_signature_algorithm_reports_AlgorithmNotAccepted</c>.</item>
/// <item>Header-driven key selection (kid resolves to <c>null</c>) — <c>SecurityInvariantsTests.Unknown_kid_is_rejected_before_the_signature_is_verified</c>.</item>
/// <item>Signature-before-claims ordering — <c>SecurityInvariantsTests.Signature_is_verified_before_claims_so_an_expired_forgery_reports_signature_mismatch</c>.</item>
/// <item>Profile downgrade (5-part envelope whose inner isn't a 3-part JWT) — <c>SecurityInvariantsTests.Encrypted_envelope_whose_plaintext_is_not_a_signed_jwt_is_rejected</c>.</item>
/// <item>GCM tag truncation — <c>SecurityInvariantsTests.Truncated_gcm_tag_is_rejected</c>.</item>
/// <item>Tampered signature segment — <c>PqJwtRoundtripTests.Tampered_signature_is_rejected</c>.</item>
/// <item>Tampered <c>enc</c>/<c>cty</c> header fields — <c>PqJwtFailureReasonTests.Tampered_enc_header_reports_AlgorithmNotAccepted</c> and <c>...Tampered_cty_header...</c>.</item>
/// <item>Replay (<c>jti</c> reuse) and replay-without-<c>exp</c> — <c>PqJwtFailureReasonTests.Second_use_of_a_jti_reports_ReplayDetected</c> and <c>...Replay_protection_requires_an_exp_claim</c>.</item>
/// <item>Non-canonical base64url, embedded whitespace, slack bits — <c>Base64UrlTests</c>.</item>
/// <item>Duplicate JSON keys in JOSE header — <c>PqJwtFailureReasonTests.Header_with_duplicate_keys_reports_MalformedJson</c>.</item>
/// <item>Oversized token DoS — <c>PqJwtFailureReasonTests.An_absurdly_long_token_is_rejected_before_parsing</c> and <c>BoundaryTests.Token_one_byte_past_max_length_is_MalformedToken</c>.</item>
/// </list>
/// </summary>
public sealed class RedTeamScenarios
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    private static string B64(string s) => Base64Url.EncodeUtf8(s);

    private static string SignCrafted(MLDsa key, string headerJson, string payloadJson)
    {
        var h = B64(headerJson);
        var p = B64(payloadJson);
        var sig = key.SignData(Encoding.ASCII.GetBytes($"{h}.{p}"));
        return $"{h}.{p}.{Base64Url.Encode(sig)}";
    }

    // ── Attack 1: header parameter pollution / key-injection ────────────

    /// <summary>
    /// <b>Attack:</b> the token's JOSE header carries one of the JOSE
    /// "where-to-get-the-key" parameters (<c>jku</c>, <c>jwk</c>,
    /// <c>x5u</c>, <c>x5c</c>) pointing at an attacker-controlled URL or
    /// embedded key. In a naive library the validator would fetch / use
    /// that key for verification — a classical algorithm-confusion variant.
    /// <para>
    /// <b>Defense:</b> the validator NEVER reads any of these fields from
    /// the token. The signature-verification key comes exclusively from
    /// the trusted <c>SignatureKeyResolver</c> (a JWKS-equivalent the
    /// host process supplies); the token's header is purely descriptive
    /// metadata. <c>PostQuantum.Jwt.Analyzers</c>'s PQJWT001 enforces the
    /// same property at compile time for *consumer* code; this test pins
    /// it for the validator itself.
    /// </para>
    /// <para>
    /// The token below is signed over a header that *includes* a malicious
    /// <c>jku</c>. We resolve <c>kid="real-key"</c> to a real ML-DSA key
    /// and validate. Validation must succeed (the signature over the
    /// jku-containing header is honestly produced by the legitimate
    /// signer), proving the validator's behaviour does not depend on the
    /// jku at all.
    /// </para>
    /// </summary>
    [PqcFact]
    public void Header_jku_jwk_x5c_are_ignored_for_key_selection()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var exp = Now + TimeSpan.FromMinutes(5);

        var maliciousHeader =
            $"{{\"alg\":\"{PqJwtAlgorithms.MLDsa65}\",\"kid\":\"real-key\"," +
            "\"jku\":\"https://attacker.example/keys.json\"," +
            "\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"unused\"}," +
            "\"x5u\":\"https://attacker.example/chain.pem\"," +
            "\"x5c\":[\"unused-cert\"]}";
        var payload = $"{{\"sub\":\"s\",\"exp\":{exp.ToUnixTimeSeconds()}}}";
        var token = SignCrafted(signingKey, maliciousHeader, payload);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureKeyResolver = kid => kid == "real-key" ? TestKeys.PublicKeyOf(signingKey) : null,
            },
            clock);

        var result = validator.Validate(token);
        Assert.NotNull(result);
    }

    // ── Attack 2: tampered inner JWT inside an encrypted envelope ────────

    /// <summary>
    /// <b>Attack:</b> the attacker captures a legitimately-encrypted token,
    /// decrypts a copy (or constructs a fresh encrypted envelope around a
    /// signed JWT whose signature byte has been flipped), and replays the
    /// encrypted form. The KEM ciphertext and AES-GCM tag verify over the
    /// outer envelope, so a library that trusted the envelope's
    /// authentication would accept the tampered inner JWT.
    /// <para>
    /// <b>Defense:</b> after decryption, the inner plaintext must be a
    /// 3-part signed JWT *and* its ML-DSA-65 signature must verify against
    /// the resolver-supplied key. The encrypted-envelope MAC is a
    /// confidentiality + transport-integrity binding, not an authenticity
    /// assertion about the inner claims. SPEC step 3 → step 6 (decrypt,
    /// then verify the inner signature).
    /// </para>
    /// <para>
    /// This test builds a legitimate signed-then-encrypted token via the
    /// public builder, then decrypts internally (so we get the inner
    /// signed JWT), flips one signature byte, and re-encrypts the tampered
    /// inner. The validator must reject with <c>SignatureMismatch</c>.
    /// </para>
    /// </summary>
    [PqcFact]
    public void Encrypted_envelope_with_tampered_inner_signature_reports_SignatureMismatch()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);

        var innerSigned = new PqJwtBuilder(clock)
            .WithSubject("attacker-controlled")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        // Flip the last char of the inner signature segment so it no longer
        // matches ML-DSA verification over the inner header.payload.
        var innerParts = innerSigned.Split('.');
        innerParts[^1] = innerParts[^1][..^1] + (innerParts[^1][^1] == 'A' ? 'B' : 'A');
        var tamperedInner = string.Join('.', innerParts);

        var envelope = EncryptArbitraryPlaintext(recipient.PublicKey, Encoding.UTF8.GetBytes(tamperedInner));

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                DecryptionKey = recipient,
            },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(envelope));
        Assert.Equal(PqJwtFailureReason.SignatureMismatch, ex.Reason);
    }

    // ── Attack 3: AAD rebinding (header swap after encryption) ───────────

    /// <summary>
    /// <b>Attack:</b> the attacker takes a legitimately-encrypted token
    /// and swaps the *encoded header* segment with a different (but still
    /// well-formed) JOSE header — for example, changing <c>cty</c> from
    /// <c>"JWT"</c> to something else. The KEM ciphertext, IV, ciphertext,
    /// and tag are left untouched. A library that decrypted purely on the
    /// inner ciphertext without binding the header would accept the
    /// swapped token.
    /// <para>
    /// <b>Defense:</b> AES-256-GCM is authenticated encryption with
    /// associated data (AEAD); this library binds the encoded JOSE header
    /// as AAD when sealing the token. Any modification to the header
    /// invalidates the tag, surfacing as <c>DecryptionFailed</c>. SPEC
    /// step 4 (decryption verifies header-as-AAD).
    /// </para>
    /// </summary>
    [PqcFact]
    public void Header_swap_after_encryption_breaks_AAD_binding()
    {
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("s")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        var parts = token.Split('.');
        // Build a different — but well-formed and algorithm-correct — header
        // and substitute it. The substitution is base64url-clean and parses
        // to the same algorithm suite, so only the AEAD tag can catch it.
        var swappedHeader = B64(
            $"{{\"alg\":\"{PqJwtAlgorithms.XWing}\"," +
            $"\"enc\":\"{PqJwtAlgorithms.Aes256Gcm}\"," +
            $"\"typ\":\"{PqJwtAlgorithms.TokenType}\"," +
            $"\"cty\":\"{PqJwtAlgorithms.TokenType}\"," +
            "\"swapped\":true}");
        parts[0] = swappedHeader;
        var rebound = string.Join('.', parts);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                DecryptionKey = recipient,
            },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(rebound));
        Assert.Equal(PqJwtFailureReason.DecryptionFailed, ex.Reason);
    }

    // ── Attack 4: kid collision (same string, different key) ─────────────

    /// <summary>
    /// <b>Attack:</b> a token is presented with <c>kid="rotated-key"</c>
    /// signed by an attacker key. The host's resolver, separately, resolves
    /// <c>"rotated-key"</c> to the legitimate ML-DSA-65 verification key.
    /// (This is the "same kid string, different actual key" race that
    /// shows up around key rotation if a kid is reused, or if an attacker
    /// guesses a current kid value and signs with their own key.)
    /// <para>
    /// <b>Defense:</b> the kid only selects the verification key; the
    /// ML-DSA-65 signature must then verify against *that* key. An
    /// attacker key never signs a verifying signature under a different
    /// public key. Fails as <c>SignatureMismatch</c>, not
    /// <c>UnknownKeyId</c> — pinning that the validator runs the
    /// expensive verify after resolution, not "trust the kid and skip
    /// the check".
    /// </para>
    /// </summary>
    [PqcFact]
    public void Kid_collision_signed_with_different_key_reports_SignatureMismatch()
    {
        using var legitimateKey = TestKeys.NewSigningKey();
        using var attackerKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithKeyId("rotated-key")
            .WithSubject("attacker")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(attackerKey)
            .Build();

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureKeyResolver = kid => kid == "rotated-key" ? TestKeys.PublicKeyOf(legitimateKey) : null,
            },
            clock);

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Equal(PqJwtFailureReason.SignatureMismatch, ex.Reason);
    }

    // ── shared helper (mirrors SecurityInvariantsTests.EncryptArbitraryPlaintext) ──

    private static string EncryptArbitraryPlaintext(XWingPublicKey recipient, ReadOnlySpan<byte> plaintext)
    {
        var header =
            $"{{\"alg\":\"{PqJwtAlgorithms.XWing}\",\"enc\":\"{PqJwtAlgorithms.Aes256Gcm}\"," +
            $"\"typ\":\"{PqJwtAlgorithms.TokenType}\",\"cty\":\"{PqJwtAlgorithms.TokenType}\"}}";
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
