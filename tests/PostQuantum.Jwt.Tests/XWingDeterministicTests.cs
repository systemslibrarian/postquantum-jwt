using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Exercises the X-Wing encapsulation path under the internal
/// <see cref="IXWingDeterministicCoins"/> seam.
/// </summary>
/// <remarks>
/// <para>
/// The BCL <c>MLKem.Encapsulate</c> draws its own randomness and exposes no
/// derandomized entry point — see <c>KNOWN-GAPS.md</c>. The seam lets us
/// inject (ct_M, ss_M) and the X25519 ephemeral private key so the
/// combiner direction can be KAT-checked against the official X-Wing
/// vectors. Production code never reaches this — the public
/// <c>XWing.Encapsulate(recipient)</c> overload has no parameter for it.
/// </para>
/// <para>
/// Additionally, a 64-iteration statistical sanity test covers the only
/// path that remains un-KAT'd (the BCL ML-KEM <c>Encapsulate</c> step
/// itself): assert that 64 encapsulations to the same recipient produce
/// 64 distinct ciphertexts and 64 distinct shared secrets, and that every
/// round-trip recovers the secret.
/// </para>
/// </remarks>
public sealed class XWingDeterministicTests
{
    public static TheoryData<int, EncapsulationVector> Vectors()
    {
        var json = File.ReadAllText(Path.Combine("TestVectors", "xwing-vectors.json"));
        var vectors = JsonSerializer.Deserialize<List<EncapsulationVector>>(json)
            ?? throw new InvalidOperationException("Could not load X-Wing test vectors.");

        var data = new TheoryData<int, EncapsulationVector>();
        for (var i = 0; i < vectors.Count; i++)
        {
            data.Add(i, vectors[i]);
        }

        return data;
    }

    /// <summary>
    /// X-Wing encapsulation under deterministic coins (vector eseed + vector
    /// ct_M and the ss_M recovered by decapsulating against the vector's
    /// recipient) must reproduce the vector's full 1120-byte ciphertext and
    /// 32-byte shared secret. KATs the combiner direction and the X25519 half.
    /// </summary>
    [PqcTheory]
    [MemberData(nameof(Vectors))]
    public void Encapsulation_under_injected_coins_reproduces_the_vector(int index, EncapsulationVector vector)
    {
        _ = index;

        using var recipientKey = XWingPrivateKey.ImportSeed(Hex(vector.Seed));
        var vectorCiphertext = Hex(vector.Ct);
        var vectorSharedSecret = Hex(vector.Ss);
        var eseed = Hex(vector.Eseed);
        Assert.Equal(64, eseed.Length);

        // The X-Wing spec splits the 64-byte eseed: first 32 bytes feed
        // ML-KEM-768 Encaps (m); last 32 bytes are the X25519 ephemeral
        // private key. The BCL has no Encaps(m, pk) entry point, so the
        // ML-KEM ciphertext + shared secret are recovered by decapsulating
        // the vector's ct_M against the recipient — that gives the same
        // (ct_M, ss_M) the spec-compliant encapsulator would have produced
        // for this m. The injected coins below feed those values back into
        // the sender path so the combiner direction is exercised end-to-end.
        var ctM = vectorCiphertext[..XWing.MlKemCiphertextLength];
        var ssM = recipientKey.MlKem.Decapsulate(ctM);
        var x25519EphemeralPrivate = eseed[32..];

        var coins = new FixedCoins(ctM, ssM, x25519EphemeralPrivate);
        var (sharedSecret, ciphertext) = XWing.Encapsulate(recipientKey.PublicKey, coins);

        Assert.Equal(vectorCiphertext, ciphertext);
        Assert.Equal(vectorSharedSecret, sharedSecret);
    }

    /// <summary>
    /// Statistical sanity: 64 production encapsulations to the same recipient
    /// must produce 64 distinct ciphertexts and 64 distinct shared secrets,
    /// and every round-trip must recover the secret. Cheap on a PQ-capable
    /// host and catches a stuck-RNG regression instantly.
    /// </summary>
    [PqcFact]
    public void X_Wing_encapsulation_to_the_same_recipient_produces_distinct_outputs_across_64_iterations()
    {
        using var recipient = XWingPrivateKey.Generate();

        var ciphertexts = new HashSet<string>(StringComparer.Ordinal);
        var sharedSecrets = new HashSet<string>(StringComparer.Ordinal);

        const int iterations = 64;
        for (var i = 0; i < iterations; i++)
        {
            var (senderSecret, ciphertext) = XWing.Encapsulate(recipient.PublicKey);
            var recipientSecret = XWing.Decapsulate(recipient, ciphertext);

            Assert.Equal(senderSecret, recipientSecret);

            Assert.True(ciphertexts.Add(Convert.ToHexString(ciphertext)),
                $"Iteration {i}: ciphertext repeated — RNG is stuck.");
            Assert.True(sharedSecrets.Add(Convert.ToHexString(senderSecret)),
                $"Iteration {i}: shared secret repeated — RNG is stuck.");
        }

        Assert.Equal(iterations, ciphertexts.Count);
        Assert.Equal(iterations, sharedSecrets.Count);
    }

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    private sealed class FixedCoins(
        byte[] mlKemCiphertext,
        byte[] mlKemSecret,
        byte[] x25519EphemeralPrivate) : IXWingDeterministicCoins
    {
        public (byte[] Ciphertext, byte[] SharedSecret)? MlKemEncapsulate(MLKem mlKem) =>
            (mlKemCiphertext, mlKemSecret);

        public byte[]? X25519EphemeralPrivateKey() => x25519EphemeralPrivate;
    }
}

/// <summary>
/// One entry from the official X-Wing test-vector file, with the encapsulation
/// seed exposed (the existing <c>XWingVector</c> only carries the fields needed
/// for the seed-keygen / decapsulation KATs).
/// </summary>
public sealed class EncapsulationVector
{
    [System.Text.Json.Serialization.JsonPropertyName("seed")]
    public string Seed { get; init; } = "";

    [System.Text.Json.Serialization.JsonPropertyName("eseed")]
    public string Eseed { get; init; } = "";

    [System.Text.Json.Serialization.JsonPropertyName("pk")]
    public string Pk { get; init; } = "";

    [System.Text.Json.Serialization.JsonPropertyName("ct")]
    public string Ct { get; init; } = "";

    [System.Text.Json.Serialization.JsonPropertyName("ss")]
    public string Ss { get; init; } = "";
}
