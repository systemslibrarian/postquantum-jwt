using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

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

    /// <summary>A process-wide BouncyCastle RNG seeded from the OS entropy source.</summary>
    internal static SecureRandom SecureRandom { get; } = new();

    /// <summary>
    /// Encapsulates a fresh shared secret to <paramref name="recipient"/>.
    /// </summary>
    /// <param name="recipient">The recipient's X-Wing public key.</param>
    /// <returns>The 32-byte shared secret and the 1120-byte ciphertext to transmit.</returns>
    internal static (byte[] SharedSecret, byte[] Ciphertext) Encapsulate(XWingPublicKey recipient)
    {
        ArgumentNullException.ThrowIfNull(recipient);

        // ML-KEM-768 half (native BCL). Wrap parse failures in PqJwtException so
        // callers see one exception family — XWingPublicKey.Import accepts on length
        // alone, so a structurally wrong key is detected here.
        using var mlKem = ImportMlKemEncapsulationKey(recipient.MlKemEncapsulationKey);
        mlKem.Encapsulate(out var mlKemCiphertext, out var mlKemSecret);

        // X25519 half (ephemeral key, BouncyCastle).
        var generator = new X25519KeyPairGenerator();
        generator.Init(new X25519KeyGenerationParameters(SecureRandom));
        var ephemeral = generator.GenerateKeyPair();
        var ephemeralCiphertext = ((X25519PublicKeyParameters)ephemeral.Public).GetEncoded();
        var x25519Secret = X25519Agree(
            (X25519PrivateKeyParameters)ephemeral.Private,
            new X25519PublicKeyParameters(recipient.X25519PublicKey));

        var sharedSecret = Combine(mlKemSecret, x25519Secret, ephemeralCiphertext, recipient.X25519PublicKey);

        var ciphertext = new byte[CiphertextLength];
        mlKemCiphertext.CopyTo(ciphertext.AsSpan(0, MlKemCiphertextLength));
        ephemeralCiphertext.CopyTo(ciphertext.AsSpan(MlKemCiphertextLength));

        CryptographicOperations.ZeroMemory(mlKemSecret);
        CryptographicOperations.ZeroMemory(x25519Secret);
        return (sharedSecret, ciphertext);
    }

    /// <summary>Recovers the shared secret from a ciphertext using the recipient's private key.</summary>
    /// <param name="privateKey">The recipient's X-Wing private key.</param>
    /// <param name="ciphertext">The 1120-byte ciphertext produced by <see cref="Encapsulate"/>.</param>
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

    private static MLKem ImportMlKemEncapsulationKey(byte[] encoded)
    {
        try
        {
            return MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encoded);
        }
        catch (CryptographicException ex)
        {
            throw new PqJwtException(
                "Invalid X-Wing public key: ML-KEM-768 encapsulation key is malformed.", ex);
        }
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
