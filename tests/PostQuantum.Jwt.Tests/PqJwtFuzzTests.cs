using System.Security.Cryptography;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Internal;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Adversarial / negative fuzzing of <see cref="PqJwtValidator.Validate(string)"/>.
/// Where <see cref="SecurityInvariantsTests"/> pins specific ordering and
/// composition guarantees, this widens the net over the <i>input space</i> to
/// defend two total properties that must hold for <b>every</b> input:
/// <list type="number">
/// <item><b>Fail-closed totality.</b> Validation either returns a result or
/// throws one of the documented fail-closed types
/// (<see cref="PqJwtException"/> / <see cref="PqJwtValidationException"/>).
/// No other exception — no <c>IndexOutOfRange</c>, <c>NullReference</c>,
/// <c>FormatException</c>, <c>JsonException</c>, <c>OverflowException</c>,
/// decoder fallbacks — may escape. This is the "no weird machine": every
/// malformed input is funnelled into the fail-closed contract.</item>
/// <item><b>No spurious acceptance.</b> None of these inputs is a genuinely
/// signed token, so none may validate. (Forging acceptance would require a
/// valid ML-DSA-65 signature over the token's own header.payload — the
/// hardness assumption — so any acceptance here is a real bug.)</item>
/// </list>
/// The single permitted non-fail-closed outcome is the documented
/// <see cref="ArgumentException"/> argument guard on a null/empty token, which
/// the generators exclude.
/// </summary>
public sealed class PqJwtFuzzTests
{
    // Built lazily so native ML-DSA / ML-KEM are touched only when a property
    // actually runs (i.e. PqcProperty did not skip on an unsupported host).
    private static readonly Lazy<Fixture> Shared = new(() => new Fixture());

    /// <summary>Arbitrary strings, fed straight in. FsCheck's string generator
    /// produces control characters, surrogate pairs, and other nasties.</summary>
    [PqcProperty(MaxTest = 500)]
    public bool Validation_is_fail_closed_for_arbitrary_strings(string? input)
    {
        // The documented null/empty argument guard is the one permitted
        // non-fail-closed throw; exclude it from the property.
        if (string.IsNullOrEmpty(input))
        {
            return true;
        }

        return RejectedCleanly(input);
    }

    /// <summary>Structurally token-shaped garbage: valid base64url segments over
    /// random bytes, in 3-part (signed) and 5-part (encrypted) layouts. This
    /// drives past the segment-count and base64url gates into the JSON / header /
    /// cryptographic-material paths that arbitrary strings rarely reach.</summary>
    [PqcProperty(MaxTest = 300)]
    public bool Validation_is_fail_closed_for_segmented_base64url_garbage(
        byte[]? a, byte[]? b, byte[]? c, byte[]? d, byte[]? e, bool fiveParts)
    {
        static string Seg(byte[]? bytes) => Base64Url.Encode(bytes ?? []);
        var token = fiveParts
            ? string.Join('.', Seg(a), Seg(b), Seg(c), Seg(d), Seg(e))
            : string.Join('.', Seg(a), Seg(b), Seg(c));
        return RejectedCleanly(token);
    }

    /// <summary>Structure-aware mutation of a genuinely valid token (signed or
    /// encrypted): flip / delete / insert / truncate / append-segment / swap-
    /// segments. Any mutation that actually changes the bytes must be rejected —
    /// the signature (and, for encrypted tokens, the AES-GCM tag and the
    /// header-as-AAD binding) covers every byte that matters.</summary>
    [PqcProperty(MaxTest = 100)]
    public bool Mutating_a_valid_token_never_makes_it_validate(bool encrypted, int kind, int position)
    {
        var token = encrypted ? Shared.Value.ValidEncryptedToken() : Shared.Value.ValidSignedToken();
        var mutated = Mutate(token, kind, position);

        // A no-op mutation leaves a legitimately valid token (correct to accept);
        // an empty result hits the documented null/empty argument guard — neither
        // is a counterexample to fail-closed totality.
        if (string.IsNullOrEmpty(mutated) || string.Equals(mutated, token, StringComparison.Ordinal))
        {
            return true;
        }

        return RejectedCleanly(mutated);
    }

    // Returns true iff the validator rejected the token through the fail-closed
    // contract. Returns false (a counterexample) if it ACCEPTED the token. Any
    // exception type other than PqJwtException propagates out — FsCheck reports
    // it, with the shrunk input, as the weird-machine bug it is.
    private static bool RejectedCleanly(string token)
    {
        try
        {
            Shared.Value.Validator.Validate(token);
            return false; // accepted — impossible without a real signature; a bug
        }
        catch (PqJwtException)
        {
            return true; // PqJwtValidationException is a PqJwtException subtype
        }
    }

    // String-total mutations (never throw): every branch returns a valid string.
    private static string Mutate(string s, int kind, int position)
    {
        if (s.Length == 0)
        {
            return s;
        }

        var i = ((position % s.Length) + s.Length) % s.Length;
        switch (((kind % 6) + 6) % 6)
        {
            case 0: // flip one character
                var chars = s.ToCharArray();
                chars[i] = chars[i] == 'A' ? 'B' : 'A';
                return new string(chars);
            case 1: // delete one character
                return s.Remove(i, 1);
            case 2: // insert one character
                return s.Insert(i, "A");
            case 3: // truncate
                return s[..i];
            case 4: // add an extra segment boundary
                return s + ".";
            default: // swap first and last segments
                var parts = s.Split('.');
                if (parts.Length >= 2)
                {
                    (parts[0], parts[^1]) = (parts[^1], parts[0]);
                    return string.Join('.', parts);
                }

                return s + "A";
        }
    }

    private sealed class Fixture
    {
        private readonly MLDsa _signingKey = TestKeys.NewSigningKey();
        private readonly XWingPrivateKey _recipient = XWingPrivateKey.Generate();

        public PqJwtValidator Validator { get; }

        public Fixture() =>
            // Lifetime checks off: this harness probes structure and cryptography,
            // not the clock (expiry is covered deterministically elsewhere).
            Validator = new PqJwtValidator(new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(_signingKey),
                DecryptionKey = _recipient,
                ValidateLifetime = false,
            });

        public string ValidSignedToken() =>
            new PqJwtBuilder()
                .WithSubject("subject")
                .SignWith(_signingKey)
                .Build();

        public string ValidEncryptedToken() =>
            new PqJwtBuilder()
                .WithSubject("subject")
                .SignWith(_signingKey)
                .EncryptFor(_recipient.PublicKey)
                .Build();
    }
}
