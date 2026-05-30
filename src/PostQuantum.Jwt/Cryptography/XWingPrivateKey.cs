using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace PostQuantum.Jwt.Cryptography;

/// <summary>
/// The private half of an X-Wing key pair (ML-KEM-768 decapsulation key + X25519
/// private key). Used to decrypt tokens addressed to its <see cref="PublicKey"/>.
/// </summary>
/// <remarks>
/// Holds key material in memory. Call <see cref="Dispose"/> (or use a
/// <c>using</c> statement) to release the underlying ML-KEM handle and best-effort
/// zero the X25519 secret.
/// </remarks>
public sealed class XWingPrivateKey : IDisposable
{
    private readonly MLKem _mlKem;
    private readonly byte[] _x25519PrivateKey;
    private bool _disposed;

    private XWingPrivateKey(MLKem mlKem, byte[] x25519PrivateKey, XWingPublicKey publicKey)
    {
        _mlKem = mlKem;
        _x25519PrivateKey = x25519PrivateKey;
        PublicKey = publicKey;
    }

    /// <summary>Gets the public key corresponding to this private key.</summary>
    public XWingPublicKey PublicKey { get; }

    internal MLKem MlKem
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _mlKem;
        }
    }

    internal byte[] X25519PrivateKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _x25519PrivateKey;
        }
    }

    /// <summary>The X-Wing key-generation seed length (32 bytes), per the spec.</summary>
    public const int SeedLength = 32;

    // expandDecapsulationKey: SHAKE-256(seed, 96) -> ML-KEM (d || z) || X25519 sk.
    private const int ExpandedLength = 96;

    /// <summary>Generates a fresh X-Wing key pair using the OS cryptographic RNG.</summary>
    /// <returns>A new <see cref="XWingPrivateKey"/> (its <see cref="PublicKey"/> carries the public half).</returns>
    public static XWingPrivateKey Generate()
    {
        var seed = RandomNumberGenerator.GetBytes(SeedLength);
        try
        {
            return ImportSeed(seed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>
    /// Derives an X-Wing key pair deterministically from a 32-byte seed, exactly as
    /// <c>expandDecapsulationKey</c> in <c>draft-connolly-cfrg-xwing-kem</c>: the seed
    /// is expanded with SHAKE-256 into the ML-KEM-768 key-generation seed (<c>d || z</c>)
    /// and the X25519 private key. This is the canonical, spec-compliant key generation.
    /// </summary>
    /// <param name="seed">A 32-byte seed.</param>
    /// <returns>The derived <see cref="XWingPrivateKey"/>.</returns>
    /// <exception cref="PqJwtException">The seed is not exactly 32 bytes.</exception>
    public static XWingPrivateKey ImportSeed(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != SeedLength)
        {
            throw new PqJwtException(
                $"Invalid X-Wing seed length: expected {SeedLength} bytes, got {seed.Length}.");
        }

        var expanded = new byte[ExpandedLength];
        try
        {
            var shake = new ShakeDigest(256);
            shake.BlockUpdate(seed);
            shake.OutputFinal(expanded);

            // expanded[0..64] = ML-KEM-768 KeyGen seed (d || z); expanded[64..96] = X25519 sk.
            var mlKem = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, expanded.AsSpan(0, 64));
            var x25519Private = expanded[64..ExpandedLength];

            var encapsulationKey = mlKem.ExportEncapsulationKey();
            var x25519Public = new X25519PrivateKeyParameters(x25519Private).GeneratePublicKey().GetEncoded();
            var publicKey = new XWingPublicKey(encapsulationKey, x25519Public);
            return new XWingPrivateKey(mlKem, x25519Private, publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expanded);
        }
    }

    /// <summary>
    /// Serializes the private key as <c>ML-KEM-768 decapsulation key || X25519 private key</c>.
    /// This is sensitive key material — protect it accordingly.
    /// </summary>
    /// <returns>The encoded private key.</returns>
    public byte[] Export()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var decapsulationKey = _mlKem.ExportDecapsulationKey();
        var result = new byte[decapsulationKey.Length + _x25519PrivateKey.Length];
        decapsulationKey.CopyTo(result.AsSpan(0, decapsulationKey.Length));
        _x25519PrivateKey.CopyTo(result.AsSpan(decapsulationKey.Length));
        CryptographicOperations.ZeroMemory(decapsulationKey);
        return result;
    }

    /// <summary>Parses a private key previously produced by <see cref="Export"/>.</summary>
    /// <param name="encoded">The encoded private key.</param>
    /// <returns>The parsed <see cref="XWingPrivateKey"/>.</returns>
    /// <exception cref="PqJwtException">The input is not a valid X-Wing private key.</exception>
    public static XWingPrivateKey Import(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length <= XWingPublicKey.X25519KeyLength)
        {
            throw new PqJwtException("Invalid X-Wing private key: input is too short.");
        }

        var split = encoded.Length - XWingPublicKey.X25519KeyLength;
        var decapsulationKey = encoded[..split].ToArray();
        var x25519Private = encoded[split..].ToArray();

        MLKem mlKem;
        try
        {
            mlKem = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, decapsulationKey);
        }
        catch (CryptographicException ex)
        {
            throw new PqJwtException("Invalid X-Wing private key: malformed ML-KEM-768 decapsulation key.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(decapsulationKey);
        }

        var encapsulationKey = mlKem.ExportEncapsulationKey();
        var x25519Public = new X25519PrivateKeyParameters(x25519Private).GeneratePublicKey().GetEncoded();
        var publicKey = new XWingPublicKey(encapsulationKey, x25519Public);
        return new XWingPrivateKey(mlKem, x25519Private, publicKey);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _mlKem.Dispose();
        CryptographicOperations.ZeroMemory(_x25519PrivateKey);
        _disposed = true;
    }
}
