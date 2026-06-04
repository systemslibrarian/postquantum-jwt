using PostQuantum.Jwt.Internal;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Deterministic locks for <see cref="Base64Url"/>'s strict, canonical decoding.
/// The property suite (<see cref="PqJwtPropertyTests"/>) checks involution and
/// URL-safety over random input; these pin the specific anti-malleability
/// behaviour that <see cref="PqJwtFuzzTests"/> surfaced: exactly one base64url
/// string maps to a given byte sequence (RFC 7515 §2).
/// </summary>
public sealed class Base64UrlTests
{
    [Fact]
    public void Canonical_encoding_round_trips()
    {
        byte[] data = [0x00, 0x01, 0x02, 0xFF, 0xAB, 0xCD];
        Assert.Equal(data, Base64Url.Decode(Base64Url.Encode(data)));
    }

    [Fact]
    public void Non_canonical_slack_bits_are_rejected()
    {
        // The single byte 0x00 encodes canonically as "AA". "AB" also decodes to
        // 0x00 under a lenient decoder — the trailing 'B' carries non-zero slack
        // bits that should be zero — so it is a non-canonical alias and must be
        // rejected to keep token strings non-malleable.
        Assert.Equal([(byte)0x00], Base64Url.Decode("AA"));
        Assert.Throws<FormatException>(() => Base64Url.Decode("AB"));
    }

    [Fact]
    public void Embedded_whitespace_is_rejected()
    {
        // Convert.FromBase64String silently ignores whitespace; the canonical
        // round-trip check rejects it.
        Assert.Throws<FormatException>(() => Base64Url.Decode("AA AA"));
    }

    [Fact]
    public void Standard_base64_alphabet_is_rejected()
    {
        // '+' and '/' belong to standard base64, not the URL-safe alphabet.
        var urlSafe = Base64Url.Encode([0xFB, 0xFF]); // contains '-' / '_' in url-safe form
        Assert.DoesNotContain('+', urlSafe);
        Assert.Throws<FormatException>(() => Base64Url.Decode("++//"));
    }
}
