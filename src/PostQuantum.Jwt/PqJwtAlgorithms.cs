namespace PostQuantum.Jwt;

/// <summary>
/// Canonical algorithm identifiers used by PostQuantum.Jwt.
/// </summary>
/// <remarks>
/// These identifiers are <b>not</b> registered in the IANA JOSE registry. They
/// describe a post-quantum hybrid scheme that the standard registry does not yet
/// cover, so tokens produced by this library are intentionally non-interoperable
/// with generic JWT tooling. See <c>SECURITY.md</c> for the full posture.
/// </remarks>
public static class PqJwtAlgorithms
{
    /// <summary>
    /// Signature algorithm: ML-DSA-65 (FIPS 204, NIST security category 3),
    /// provided by the native .NET <see cref="System.Security.Cryptography.MLDsa"/> primitive.
    /// </summary>
    public const string MLDsa65 = "ML-DSA-65";

    /// <summary>
    /// Key-agreement algorithm: X-Wing, the hybrid KEM combining X25519 and
    /// ML-KEM-768 (per <c>draft-connolly-cfrg-xwing-kem</c>).
    /// </summary>
    public const string XWing = "X-Wing";

    /// <summary>
    /// Content-encryption algorithm: AES-256 in Galois/Counter Mode (A256GCM).
    /// </summary>
    public const string Aes256Gcm = "A256GCM";

    /// <summary>The token type header value (<c>typ</c>).</summary>
    public const string TokenType = "JWT";
}
