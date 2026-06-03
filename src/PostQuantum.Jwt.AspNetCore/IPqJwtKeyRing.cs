using System.Security.Cryptography;

namespace PostQuantum.Jwt.AspNetCore;

/// <summary>
/// A directory of ML-DSA-65 verification keys keyed by <c>kid</c>. Used to
/// supply <see cref="PqJwtValidationParameters.SignatureKeyResolver"/> a
/// thread-safe lookup; implementations can be backed by in-memory state, a
/// configuration system, or an HTTP fetch from a trusted endpoint.
/// </summary>
/// <remarks>
/// This is the post-quantum analogue of a JWKS endpoint. This library does not
/// implement the JWK/JWKS representation for ML-DSA keys, so the over-the-wire
/// format is intentionally trivial: a JSON object whose keys are <c>kid</c>
/// strings and whose values are base64 of the raw ML-DSA-65 public key bytes.
/// Like the rest of the suite, this key-distribution format is for controlled
/// issuer/verifier systems, not generic JWKS interoperability.
/// </remarks>
public interface IPqJwtKeyRing
{
    /// <summary>
    /// Resolves a verification key for a given <c>kid</c>, or
    /// <see langword="null"/> if the kid is not known.
    /// </summary>
    /// <param name="keyId">The token's <c>kid</c> header value (may be <see langword="null"/>).</param>
    /// <returns>The verification key, or <see langword="null"/>.</returns>
    MLDsa? Resolve(string? keyId);
}
