using System.Text;

namespace PostQuantum.Jwt.Internal;

/// <summary>
/// Minimal base64url (RFC 7515 §2) helpers: no padding, URL-safe alphabet.
/// </summary>
internal static class Base64Url
{
    internal static string Encode(ReadOnlySpan<byte> data) => Base64Url.ToString(data);

    internal static string EncodeUtf8(string value) =>
        Base64Url.ToString(Encoding.UTF8.GetBytes(value));

    internal static byte[] Decode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Base64UrlDecode(value);
    }

    internal static string DecodeToUtf8(string value) =>
        Encoding.UTF8.GetString(Decode(value));

    private static string ToString(ReadOnlySpan<byte> data)
    {
        // Convert to base64 then translate to the URL-safe alphabet and strip padding.
        var base64 = Convert.ToBase64String(data);
        var sb = new StringBuilder(base64.Length);
        foreach (var c in base64)
        {
            switch (c)
            {
                case '+': sb.Append('-'); break;
                case '/': sb.Append('_'); break;
                case '=': break; // drop padding
                default: sb.Append(c); break;
            }
        }

        return sb.ToString();
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var sb = new StringBuilder(value.Length + 3);
        foreach (var c in value)
        {
            switch (c)
            {
                case '-': sb.Append('+'); break;
                case '_': sb.Append('/'); break;
                default: sb.Append(c); break;
            }
        }

        switch (sb.Length % 4)
        {
            case 2: sb.Append("=="); break;
            case 3: sb.Append('='); break;
            case 1: throw new FormatException("Invalid base64url string.");
            default: break;
        }

        return Convert.FromBase64String(sb.ToString());
    }
}
