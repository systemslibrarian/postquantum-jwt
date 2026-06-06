// RejectionExplainer
//
// Turns a PqJwtValidationException into a plain-language explanation of WHY the
// token was rejected. Branches on the strongly-typed PqJwtFailureReason enum on
// the exception — the same enum that backs the validator's typed-reason
// taxonomy and the bounded-cardinality metric tag. The exception message is
// only used as the unspecified-case fallback. This is the right pattern for
// consumers: it's stable across library versions, immune to message-text
// changes and to satellite-assembly localisation, and an enum-switch
// exhaustiveness analyser will flag any new failure reason the library adds.
//
// It lives in the shared samples project (Pq.Samples.Shared) so multiple
// samples can share one copy without it drifting between them.
//
// To God be the glory — 1 Corinthians 10:31.

using PostQuantum.Jwt;

namespace Pq.Samples.Shared;

public static class RejectionExplainer
{
    /// <summary>
    /// A short headline ("what happened") and a one-line "why it matters",
    /// derived from the typed PqJwtFailureReason on the fail-closed
    /// validator's exception.
    /// </summary>
    public static (string What, string Why) Explain(PqJwtValidationException ex) => ex.Reason switch
    {
        PqJwtFailureReason.SignatureMismatch => (
            "Signature did not verify",
            "The token was altered after signing, or signed by a different key. ML-DSA-65 over the header+payload no longer matches."),

        PqJwtFailureReason.SignatureMalformed => (
            "Signature segment is corrupt",
            "The signature bytes aren't valid base64url — the token was truncated or mangled in transit."),

        PqJwtFailureReason.MalformedEncoding => (
            "Segment is not valid base64url",
            "One of the token's segments isn't canonical base64url. Non-canonical encodings are rejected to prevent token-string malleability."),

        PqJwtFailureReason.Expired => (
            "Token expired",
            "The 'exp' instant is in the past (beyond the allowed clock skew). Expiry is enforced by default; there is no opt-out."),

        PqJwtFailureReason.NotYetValid => (
            "Token not yet valid",
            "The 'nbf' instant is in the future. The token is being presented before its activation time."),

        PqJwtFailureReason.MissingExpiration => (
            "No expiry claim",
            "Every token must carry 'exp'. A token with no expiry is rejected rather than treated as eternal."),

        PqJwtFailureReason.ReplayDetected => (
            "Replay detected",
            "This 'jti' was already seen by the replay cache. The same token cannot be used twice when replay protection is on."),

        PqJwtFailureReason.MissingJwtId => (
            "Replay protection without a jti",
            "Replay protection is enabled but the token carries no 'jti' to track. It is refused rather than silently allowed."),

        PqJwtFailureReason.IssuerMismatch => (
            "Issuer mismatch",
            "The 'iss' claim does not equal the configured ValidIssuer. The token was minted for a different issuer."),

        PqJwtFailureReason.AudienceMismatch => (
            "Audience mismatch",
            "The 'aud' claim does not include the configured ValidAudience. The token was minted for a different recipient."),

        PqJwtFailureReason.AlgorithmNotAccepted => (
            "Algorithm not accepted",
            "The validator accepts exactly one suite (ML-DSA-65 / X-Wing / A256GCM). It never trusts the token's own 'alg' to pick a path — that's how 'alg: none' and downgrade attacks are foreclosed."),

        PqJwtFailureReason.UnknownKeyId => (
            "Unknown key id",
            "The 'kid' resolved to no key in the ring. An unknown signing key fails closed instead of being trusted."),

        PqJwtFailureReason.DecryptionFailed => (
            "Decryption / tag check failed",
            "The AES-256-GCM tag didn't authenticate, or the wrong X-Wing private key was used. Ciphertext integrity is enforced."),

        PqJwtFailureReason.KeyAgreementMalformed => (
            "Malformed key-agreement material",
            "The X-Wing encapsulation in the token is structurally invalid."),

        PqJwtFailureReason.InnerNotSigned => (
            "Inner token isn't a signed JWT",
            "After decryption, the contents weren't a valid signed token — the sign-then-encrypt invariant was violated."),

        PqJwtFailureReason.MalformedJson => (
            "Header or payload isn't valid JSON",
            "The decoded segment didn't parse as JSON. The token is structurally invalid."),

        PqJwtFailureReason.MalformedPayload => (
            "Payload isn't a JSON object",
            "The decoded payload was valid JSON but not a JSON object. The token is structurally invalid."),

        PqJwtFailureReason.MalformedToken => (
            "Wrong segment count",
            "A signed token has 3 segments and an encrypted one has 5. This token had neither — it isn't a PostQuantum.Jwt token."),

        PqJwtFailureReason.InvalidHeader => (
            "Invalid header field",
            "A required JOSE header field was missing or carried an unexpected value (for example a missing 'cty' on an encrypted token)."),

        PqJwtFailureReason.MalformedTimeClaim => (
            "Malformed time claim",
            "An 'exp' or 'nbf' claim was present but not an integer Unix-time value."),

        PqJwtFailureReason.CryptographicMaterial => (
            "Cryptographic material failed a primitive check",
            "A primitive key/length/format check on cryptographic bytes inside the token failed during parsing."),

        // Fall back to the real message rather than fabricate a reason. Only
        // reached when the library reports an Unspecified reason (legacy
        // constructor) or when a future library version adds a reason this
        // sample doesn't know about yet.
        _ => ("Rejected", ex.Message),
    };
}
