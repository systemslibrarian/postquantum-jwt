using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.Tests;

public sealed class XWingTests
{
    [PqcFact]
    public void Encapsulate_then_decapsulate_yields_the_same_shared_secret()
    {
        using var recipient = XWingPrivateKey.Generate();

        var (senderSecret, ciphertext) = XWing.Encapsulate(recipient.PublicKey);
        var recipientSecret = XWing.Decapsulate(recipient, ciphertext);

        Assert.Equal(XWing.SharedSecretLength, senderSecret.Length);
        Assert.Equal(XWing.CiphertextLength, ciphertext.Length);
        Assert.Equal(senderSecret, recipientSecret);
    }

    [PqcFact]
    public void Public_key_round_trips_through_export_import()
    {
        using var key = XWingPrivateKey.Generate();
        var exported = key.PublicKey.Export();

        var imported = XWingPublicKey.Import(exported);

        var (secret, ciphertext) = XWing.Encapsulate(imported);
        Assert.Equal(secret, XWing.Decapsulate(key, ciphertext));
    }

    [PqcFact]
    public void Private_key_round_trips_through_export_import()
    {
        using var original = XWingPrivateKey.Generate();
        var (secret, ciphertext) = XWing.Encapsulate(original.PublicKey);

        using var restored = XWingPrivateKey.Import(original.Export());

        Assert.Equal(secret, XWing.Decapsulate(restored, ciphertext));
    }

    [PqcFact]
    public void A_different_recipient_cannot_recover_the_secret()
    {
        using var recipient = XWingPrivateKey.Generate();
        using var stranger = XWingPrivateKey.Generate();

        var (senderSecret, ciphertext) = XWing.Encapsulate(recipient.PublicKey);
        var strangerSecret = XWing.Decapsulate(stranger, ciphertext);

        // ML-KEM decapsulation never throws (implicit rejection), but the
        // combined secret must differ for the wrong key.
        Assert.NotEqual(senderSecret, strangerSecret);
    }

    [Fact]
    public void Import_rejects_a_wrong_length_public_key()
    {
        var ex = Assert.Throws<PqJwtException>(() => XWingPublicKey.Import(new byte[10]));
        Assert.Contains("public key length", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
