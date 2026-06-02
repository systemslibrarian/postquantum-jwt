// RejectionExplainer
//
// Turns a PqJwtValidationException into a plain-language explanation of WHY the
// token was rejected. The mapping keys off the real messages the validator
// throws (see PqJwtValidator.cs) — when none match, we fall back to the raw
// message rather than inventing a reason. It lives in the shared samples
// project (Pq.Samples.Shared) because it is coupled to the validator's exact
// exception messages and must not drift between samples.
//
// To God be the glory — 1 Corinthians 10:31.

using PostQuantum.Jwt;

namespace Pq.Samples.Shared;

public static class RejectionExplainer
{
    /// <summary>
    /// A short headline ("what happened") and a one-line "why it matters",
    /// derived from the exception the fail-closed validator threw.
    /// </summary>
    public static (string What, string Why) Explain(PqJwtValidationException ex)
    {
        string m = ex.Message;

        // Order matters: check the most specific signals first.
        if (Has(m, "signature verification failed"))
            return ("Signature did not verify",
                "The token was altered after signing, or signed by a different key. ML-DSA-65 over the header+payload no longer matches.");

        if (Has(m, "not valid base64url"))
            return ("Signature segment is corrupt",
                "The signature bytes aren't valid base64url — the token was truncated or mangled in transit.");

        if (Has(m, "expired at"))
            return ("Token expired",
                "The 'exp' instant is in the past (beyond the allowed clock skew). Expiry is enforced by default; there is no opt-out.");

        if (Has(m, "not valid before"))
            return ("Token not yet valid",
                "The 'nbf' instant is in the future. The token is being presented before its activation time.");

        if (Has(m, "missing the required 'exp'"))
            return ("No expiry claim",
                "Every token must carry 'exp'. A token with no expiry is rejected rather than treated as eternal.");

        if (Has(m, "replay detected"))
            return ("Replay detected",
                "This 'jti' was already seen by the replay cache. The same token cannot be used twice when replay protection is on.");

        if (Has(m, "no 'jti'"))
            return ("Replay protection without a jti",
                "Replay protection is enabled but the token carries no 'jti' to track. It is refused rather than silently allowed.");

        if (Has(m, "issuer"))
            return ("Issuer mismatch",
                "The 'iss' claim does not equal the configured ValidIssuer. The token was minted for a different issuer.");

        if (Has(m, "audience"))
            return ("Audience mismatch",
                "The 'aud' claim does not include the configured ValidAudience. The token was minted for a different recipient.");

        if (Has(m, "Unsupported or disallowed signature algorithm") || Has(m, "Unsupported key-agreement") || Has(m, "Unsupported content-encryption"))
            return ("Algorithm not accepted",
                "The validator accepts exactly one suite (ML-DSA-65 / X-Wing / A256GCM). It never trusts the token's own 'alg' to pick a path — that's how 'alg: none' and downgrade attacks are foreclosed.");

        if (Has(m, "No verification key was resolved for kid"))
            return ("Unknown key id",
                "The 'kid' resolved to no key in the ring. An unknown signing key fails closed instead of being trusted.");

        if (Has(m, "decryption failed") || Has(m, "authentication tag mismatch"))
            return ("Decryption / tag check failed",
                "The AES-256-GCM tag didn't authenticate, or the wrong X-Wing private key was used. Ciphertext integrity is enforced.");

        if (Has(m, "key-agreement material is malformed"))
            return ("Malformed key-agreement material",
                "The X-Wing encapsulation in the token is structurally invalid.");

        if (Has(m, "Decrypted content is not a signed JWT"))
            return ("Inner token isn't a signed JWT",
                "After decryption, the contents weren't a valid signed token — the sign-then-encrypt invariant was violated.");

        if (Has(m, "payload is not valid JSON") || Has(m, "payload is not a JSON object"))
            return ("Payload isn't a JSON object",
                "The decoded payload didn't parse as a JSON object. The token is structurally invalid.");

        if (Has(m, "Malformed token: expected") || Has(m, "malformed structure"))
            return ("Wrong segment count",
                "A signed token has 3 segments and an encrypted one has 5. This token had neither — it isn't a PostQuantum.Jwt token.");

        // Fall back to the real message rather than fabricate a reason.
        return ("Rejected", m);
    }

    private static bool Has(string haystack, string needle) =>
        haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);
}
