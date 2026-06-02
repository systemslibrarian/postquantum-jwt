namespace PostQuantum.Jwt;

/// <summary>
/// A coarse, stable categorization of <em>why</em> a token was rejected, carried
/// on <see cref="PqJwtValidationException.Reason"/>. The set is deliberately small
/// and closed so it is safe to use as a metric dimension (bounded cardinality) and
/// to branch on in consumer code without parsing exception messages. A value here
/// never carries token contents, claim values, or key material — only the
/// category of failure.
/// </summary>
public enum PqJwtFailureReason
{
    /// <summary>No specific reason was recorded (e.g. an exception created through a legacy constructor).</summary>
    Unspecified = 0,

    /// <summary>The compact serialization had the wrong number of segments.</summary>
    MalformedToken,

    /// <summary>A segment was not valid Base64Url.</summary>
    MalformedEncoding,

    /// <summary>A header or payload segment was not valid JSON.</summary>
    MalformedJson,

    /// <summary>The payload decoded to valid JSON that was not a JSON object.</summary>
    MalformedPayload,

    /// <summary>A required header field was missing or had an unexpected value (for example <c>cty</c> on an encrypted token).</summary>
    InvalidHeader,

    /// <summary>The header declared an algorithm outside the supported suite (signature, key-agreement, or content-encryption).</summary>
    AlgorithmNotAccepted,

    /// <summary>The signature segment was not valid Base64Url.</summary>
    SignatureMalformed,

    /// <summary>The signature did not verify against the resolved verification key.</summary>
    SignatureMismatch,

    /// <summary>No verification key could be resolved for the token's <c>kid</c>.</summary>
    UnknownKeyId,

    /// <summary>The X-Wing key-agreement material in an encrypted token was malformed.</summary>
    KeyAgreementMalformed,

    /// <summary>Decryption failed — a tampered ciphertext, bad authentication tag, or wrong key.</summary>
    DecryptionFailed,

    /// <summary>The decrypted content of an encrypted token was not a signed JWT.</summary>
    InnerNotSigned,

    /// <summary>An <c>exp</c> or <c>nbf</c> claim was present but not an integer Unix time (e.g. a string or fractional number).</summary>
    MalformedTimeClaim,

    /// <summary>The token's <c>exp</c> is in the past (beyond the allowed clock skew).</summary>
    Expired,

    /// <summary>The token's <c>nbf</c> is in the future (beyond the allowed clock skew).</summary>
    NotYetValid,

    /// <summary>Expiration was required but the token had no <c>exp</c> claim.</summary>
    MissingExpiration,

    /// <summary>The token's <c>iss</c> did not match the expected issuer.</summary>
    IssuerMismatch,

    /// <summary>The token's <c>aud</c> did not include the expected audience.</summary>
    AudienceMismatch,

    /// <summary>Replay protection was active but the token carried no <c>jti</c> claim.</summary>
    MissingJwtId,

    /// <summary>The token's <c>jti</c> was already seen — a replay.</summary>
    ReplayDetected,

    /// <summary>A primitive cryptographic-material check failed while parsing the token.</summary>
    CryptographicMaterial,
}
