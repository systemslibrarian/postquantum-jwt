using System.Security.Cryptography;

namespace PostQuantum.Jwt.Cryptography;

/// <summary>
/// The public half of an X-Wing key pair: an ML-KEM-768 encapsulation key
/// concatenated with an X25519 public key. Hand this to a sender so they can
/// encrypt a token to you.
/// </summary>
public sealed class XWingPublicKey
{
    internal const int MlKemEncapsulationKeyLength = 1184; // ML-KEM-768, FIPS 203
    internal const int X25519KeyLength = 32;
    internal const int EncodedLength = MlKemEncapsulationKeyLength + X25519KeyLength; // 1216

    internal XWingPublicKey(byte[] mlKemEncapsulationKey, byte[] x25519PublicKey)
    {
        MlKemEncapsulationKey = mlKemEncapsulationKey;
        X25519PublicKey = x25519PublicKey;
    }

    internal byte[] MlKemEncapsulationKey { get; }

    internal byte[] X25519PublicKey { get; }

    /// <summary>
    /// Serializes the public key as <c>ML-KEM-768 encapsulation key || X25519 public key</c>
    /// (1216 bytes). Safe to share publicly.
    /// </summary>
    /// <returns>The encoded public key.</returns>
    public byte[] Export()
    {
        var result = new byte[EncodedLength];
        MlKemEncapsulationKey.CopyTo(result.AsSpan(0, MlKemEncapsulationKeyLength));
        X25519PublicKey.CopyTo(result.AsSpan(MlKemEncapsulationKeyLength));
        return result;
    }

    /// <summary>Parses a public key previously produced by <see cref="Export"/>.</summary>
    /// <param name="encoded">The 1216-byte encoded public key.</param>
    /// <returns>The parsed <see cref="XWingPublicKey"/>.</returns>
    /// <exception cref="PqJwtException">
    /// The input is not a valid X-Wing public key — either wrong length, or the
    /// ML-KEM-768 encapsulation key portion is structurally invalid. Both stages
    /// are validated at import time so consumers handling untrusted key material
    /// see a single exception boundary on ingestion rather than a later
    /// cryptographic failure during encryption.
    /// </exception>
    public static XWingPublicKey Import(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != EncodedLength)
        {
            throw new PqJwtException(
                $"Invalid X-Wing public key length: expected {EncodedLength} bytes, got {encoded.Length}.");
        }

        var mlKem = encoded[..MlKemEncapsulationKeyLength].ToArray();
        var x25519 = encoded[MlKemEncapsulationKeyLength..].ToArray();

        // Eagerly parse the ML-KEM-768 encapsulation key so a malformed public key
        // fails on Import rather than later inside XWing.Encapsulate. The parsed
        // handle is immediately disposed — XWingPublicKey holds no native state
        // and is intentionally not IDisposable (it's just public bytes).
        try
        {
            using var parsed = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, mlKem);
        }
        catch (CryptographicException ex)
        {
            throw new PqJwtException(
                "Invalid X-Wing public key: ML-KEM-768 encapsulation key is malformed.", ex);
        }

        return new XWingPublicKey(mlKem, x25519);
    }
}
