namespace PostQuantum.Jwt;

/// <summary>
/// Canonical algorithm identifiers used by PostQuantum.Jwt.
/// </summary>
/// <remarks>
/// <para>
/// <c>ML-DSA-65</c> (RFC 9964) and <c>A256GCM</c> (RFC 7518) are registered JOSE
/// identifiers, but the <c>X-Wing</c> key-management profile that ties them
/// together here is <b>not</b> a standardized JOSE/JWE profile. Tokens produced
/// by this library are therefore intentionally non-interoperable with generic
/// JWT tooling and are intended for controlled issuer/verifier systems.
/// </para>
/// <para>
/// Signing is ML-DSA-65 only (post-quantum, not a hybrid classical + PQ
/// signature); the hybrid construction applies to the optional confidentiality
/// path. See <c>SECURITY.md</c> for the full posture.
/// </para>
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
