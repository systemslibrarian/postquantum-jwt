using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace PostQuantum.Jwt.Cryptography;

/// <summary>
/// The X-Wing hybrid KEM (<c>draft-connolly-cfrg-xwing-kem</c>): ML-KEM-768 from
/// the native .NET BCL combined with X25519 from BouncyCastle, mixed through a
/// SHA3-256 combiner. The 32-byte shared secret is used directly as an
/// AES-256-GCM content-encryption key.
/// </summary>
/// <remarks>
/// The combiner is <c>SHA3-256(ss_M || ss_X || ct_X || pk_X || label)</c> where
/// <c>label = 0x5C 0x2E 0x2F 0x2F 0x5E 0x5C</c> (the ASCII bytes <c>\.//^\</c>).
/// Validated against the official X-Wing known-answer test vectors.
/// </remarks>
internal static class XWing
{
    internal const int MlKemCiphertextLength = 1088; // ML-KEM-768, FIPS 203
    internal const int CiphertextLength = MlKemCiphertextLength + XWingPublicKey.X25519KeyLength; // 1120
    internal const int SharedSecretLength = 32;

    // ASCII bytes for "\.//^\" — the X-Wing combiner domain-separation label.
    private static readonly byte[] Label = [0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C];

    /// <summary>
    /// Production encapsulation: uses the OS CSPRNG
    /// (<see cref="RandomNumberGenerator"/>) for the X25519 ephemeral half
    /// and the BCL <see cref="MLKem"/> randomized
    /// <see cref="MLKem.Encapsulate(out byte[], out byte[])"/> for the
    /// post-quantum half.
    /// </summary>
    /// <param name="recipient">The recipient's X-Wing public key.</param>
    /// <returns>The 32-byte shared secret and the 1120-byte ciphertext to transmit.</returns>
    internal static (byte[] SharedSecret, byte[] Ciphertext) Encapsulate(XWingPublicKey recipient)
        => Encapsulate(recipient, coins: null);

    /// <summary>
    /// Test-only overload. Production code MUST pass
    /// <paramref name="coins"/> = <see langword="null"/> (or use the
    /// no-arg overload, which does so). Each coin-source method may return
    /// <see langword="null"/> to fall back to the production CSPRNG / BCL
    /// ML-KEM, in which case the path is bit-identical to the production
    /// overload. The overload itself and the
    /// <see cref="IXWingDeterministicCoins"/> interface are <c>internal</c>
    /// and reachable only via
    /// <c>InternalsVisibleTo("PostQuantum.Jwt.Tests")</c>.
    /// </summary>
    internal static (byte[] SharedSecret, byte[] Ciphertext) Encapsulate(
        XWingPublicKey recipient,
        IXWingDeterministicCoins? coins)
    {
        ArgumentNullException.ThrowIfNull(recipient);

        // ML-KEM-768 half (native BCL). XWingPublicKey.Import has already parsed
        // and rejected structurally invalid keys, so this re-import is the
        // straight-line happy path.
        using var mlKem = MLKem.ImportEncapsulationKey(
            MLKemAlgorithm.MLKem768, recipient.MlKemEncapsulationKey);

        byte[] mlKemCiphertext;
        byte[] mlKemSecret;
        var injectedMlKem = coins?.MlKemEncapsulate(mlKem);
        if (injectedMlKem is { } pair)
        {
            mlKemCiphertext = pair.Ciphertext;
            mlKemSecret = pair.SharedSecret;
        }
        else
        {
            mlKem.Encapsulate(out mlKemCiphertext, out mlKemSecret);
        }

        // X25519 half. The ephemeral private key is 32 bytes from the BCL CSPRNG
        // in production; a test seam may inject a fixed 32-byte value.
        var ephemeralPrivateBytes = coins?.X25519EphemeralPrivateKey()
            ?? RandomNumberGenerator.GetBytes(XWingPublicKey.X25519KeyLength);
        try
        {
            var ephemeralPrivate = new X25519PrivateKeyParameters(ephemeralPrivateBytes);
            var ephemeralCiphertext = ephemeralPrivate.GeneratePublicKey().GetEncoded();
            var x25519Secret = X25519Agree(
                ephemeralPrivate,
                new X25519PublicKeyParameters(recipient.X25519PublicKey));

            var sharedSecret = Combine(mlKemSecret, x25519Secret, ephemeralCiphertext, recipient.X25519PublicKey);

            var ciphertext = new byte[CiphertextLength];
            mlKemCiphertext.CopyTo(ciphertext.AsSpan(0, MlKemCiphertextLength));
            ephemeralCiphertext.CopyTo(ciphertext.AsSpan(MlKemCiphertextLength));

            CryptographicOperations.ZeroMemory(mlKemSecret);
            CryptographicOperations.ZeroMemory(x25519Secret);
            return (sharedSecret, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ephemeralPrivateBytes);
        }
    }

    /// <summary>Recovers the shared secret from a ciphertext using the recipient's private key.</summary>
    /// <param name="privateKey">The recipient's X-Wing private key.</param>
    /// <param name="ciphertext">The 1120-byte ciphertext produced by <see cref="Encapsulate(XWingPublicKey)"/>.</param>
    /// <returns>The 32-byte shared secret.</returns>
    /// <exception cref="PqJwtException">The ciphertext is malformed.</exception>
    internal static byte[] Decapsulate(XWingPrivateKey privateKey, ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        if (ciphertext.Length != CiphertextLength)
        {
            throw new PqJwtException(
                $"Invalid X-Wing ciphertext length: expected {CiphertextLength} bytes, got {ciphertext.Length}.");
        }

        var mlKemCiphertext = ciphertext[..MlKemCiphertextLength].ToArray();
        var x25519Ciphertext = ciphertext[MlKemCiphertextLength..].ToArray();

        var mlKemSecret = privateKey.MlKem.Decapsulate(mlKemCiphertext);
        var x25519Secret = X25519Agree(
            new X25519PrivateKeyParameters(privateKey.X25519PrivateKey),
            new X25519PublicKeyParameters(x25519Ciphertext));

        var sharedSecret = Combine(
            mlKemSecret, x25519Secret, x25519Ciphertext, privateKey.PublicKey.X25519PublicKey);

        CryptographicOperations.ZeroMemory(mlKemSecret);
        CryptographicOperations.ZeroMemory(x25519Secret);
        return sharedSecret;
    }

    private static byte[] X25519Agree(X25519PrivateKeyParameters privateKey, X25519PublicKeyParameters publicKey)
    {
        var agreement = new X25519Agreement();
        agreement.Init(privateKey);
        var secret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(publicKey, secret, 0);
        return secret;
    }

    private static byte[] Combine(
        ReadOnlySpan<byte> mlKemSecret,
        ReadOnlySpan<byte> x25519Secret,
        ReadOnlySpan<byte> x25519Ciphertext,
        ReadOnlySpan<byte> x25519PublicKey)
    {
        // Per draft-connolly-cfrg-xwing-kem, the label is concatenated LAST:
        //   SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
        var sha3 = new Sha3Digest(256);
        Update(sha3, mlKemSecret);
        Update(sha3, x25519Secret);
        Update(sha3, x25519Ciphertext);
        Update(sha3, x25519PublicKey);
        Update(sha3, Label);

        var output = new byte[SharedSecretLength];
        sha3.DoFinal(output, 0);
        return output;

        static void Update(Sha3Digest digest, ReadOnlySpan<byte> data) =>
            digest.BlockUpdate(data);
    }
}
