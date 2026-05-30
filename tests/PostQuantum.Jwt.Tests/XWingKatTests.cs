using System.Text.Json;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Known-answer tests against the official X-Wing test vectors
/// (<c>spec/test-vectors.json</c> from <c>draft-connolly-cfrg-xwing-kem</c>).
/// </summary>
/// <remarks>
/// We validate the deterministic paths that the .NET BCL can reproduce:
/// seed-based key generation (must yield the vector's public key) and
/// decapsulation + the SHA3-256 combiner (must yield the vector's shared secret).
/// The encapsulation path is intentionally not KAT-checked here: the BCL
/// <c>MLKem.Encapsulate</c> draws its own randomness and offers no derandomized
/// ("Encaps_derand") entry point, so the vector's <c>eseed</c> cannot be injected.
/// Encapsulation is instead covered by the round-trip tests in <c>XWingTests</c>.
/// </remarks>
public sealed class XWingKatTests
{
    public static TheoryData<int, XWingVector> Vectors()
    {
        var json = File.ReadAllText(Path.Combine("TestVectors", "xwing-vectors.json"));
        var vectors = JsonSerializer.Deserialize<List<XWingVector>>(json)
            ?? throw new InvalidOperationException("Could not load X-Wing test vectors.");

        var data = new TheoryData<int, XWingVector>();
        for (var i = 0; i < vectors.Count; i++)
        {
            data.Add(i, vectors[i]);
        }

        return data;
    }

    [PqcTheory]
    [MemberData(nameof(Vectors))]
    public void Seed_keygen_reproduces_the_vector_public_key(int index, XWingVector vector)
    {
        _ = index;
        using var key = XWingPrivateKey.ImportSeed(Hex(vector.Seed));

        Assert.Equal(vector.Pk, ToHex(key.PublicKey.Export()));
    }

    [PqcTheory]
    [MemberData(nameof(Vectors))]
    public void Decapsulating_the_vector_ciphertext_yields_the_vector_shared_secret(int index, XWingVector vector)
    {
        _ = index;
        using var key = XWingPrivateKey.ImportSeed(Hex(vector.Seed));

        var sharedSecret = XWing.Decapsulate(key, Hex(vector.Ct));

        Assert.Equal(vector.Ss, ToHex(sharedSecret));
    }

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}

/// <summary>One entry from the official X-Wing test-vector file.</summary>
public sealed class XWingVector
{
    [System.Text.Json.Serialization.JsonPropertyName("seed")]
    public string Seed { get; init; } = "";

    [System.Text.Json.Serialization.JsonPropertyName("pk")]
    public string Pk { get; init; } = "";

    [System.Text.Json.Serialization.JsonPropertyName("ct")]
    public string Ct { get; init; } = "";

    [System.Text.Json.Serialization.JsonPropertyName("ss")]
    public string Ss { get; init; } = "";
}
