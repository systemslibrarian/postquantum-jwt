using System.Security.Cryptography;

namespace PostQuantum.Jwt.Cryptography;

/// <summary>
/// Test-only seam that lets the test suite exercise the X-Wing combiner and
/// the X25519 ephemeral half of <see cref="XWing.Encapsulate(XWingPublicKey)"/>
/// against known-answer inputs.
/// </summary>
/// <remarks>
/// <para>
/// Production code never reaches this — the public
/// <see cref="XWing.Encapsulate(XWingPublicKey)"/> overload calls the OS CSPRNG
/// (<see cref="RandomNumberGenerator"/>) and the BCL <see cref="MLKem"/>
/// exclusively. Both this interface and the
/// <see cref="XWing.Encapsulate(XWingPublicKey, IXWingDeterministicCoins?)"/>
/// overload that accepts it are <c>internal</c> and reachable only through
/// <c>InternalsVisibleTo("PostQuantum.Jwt.Tests")</c>.
/// </para>
/// <para>
/// Each method returns <see langword="null"/> to fall back to the production
/// randomness source — so even an in-scope coin source never weakens
/// randomness unless a test explicitly asks for it.
/// </para>
/// <para>
/// This seam exists because the BCL <see cref="MLKem.Encapsulate(out byte[], out byte[])"/>
/// exposes no derandomized entry point, blocking a true ML-KEM encapsulation KAT.
/// It lets the suite KAT what *can* be made deterministic — the X-Wing
/// combiner and the X25519 ephemeral half — without ever giving production
/// code a way to reduce randomness.
/// </para>
/// </remarks>
internal interface IXWingDeterministicCoins
{
    /// <summary>
    /// Optionally override the ML-KEM-768 encapsulation step. Return
    /// <see langword="null"/> to fall back to the randomized
    /// <see cref="MLKem.Encapsulate(out byte[], out byte[])"/>.
    /// </summary>
    /// <param name="mlKem">The ML-KEM-768 instance that would otherwise encapsulate.</param>
    /// <returns>A fixed (ciphertext, sharedSecret) pair to inject, or <see langword="null"/>.</returns>
    (byte[] Ciphertext, byte[] SharedSecret)? MlKemEncapsulate(MLKem mlKem);

    /// <summary>
    /// Optionally override the 32-byte X25519 ephemeral private key. Return
    /// <see langword="null"/> to fall back to
    /// <see cref="RandomNumberGenerator.GetBytes(int)"/>.
    /// </summary>
    /// <returns>A fixed 32-byte ephemeral private key, or <see langword="null"/>.</returns>
    byte[]? X25519EphemeralPrivateKey();
}
