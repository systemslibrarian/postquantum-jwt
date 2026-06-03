using System.Diagnostics.Metrics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Internal;

namespace PostQuantum.Jwt;

/// <summary>
/// Validates JOSE-style post-quantum tokens (ML-DSA-65 signatures, optional
/// hybrid X-Wing-style confidentiality). Fail-closed by design: any problem with
/// structure, decryption, signature, or claims raises
/// <see cref="PqJwtValidationException"/> rather than returning a degraded result.
/// </summary>
/// <remarks>Instances are immutable and safe to reuse across threads.</remarks>
public sealed class PqJwtValidator
{
    private const int SignedPartCount = 3;
    private const int EncryptedPartCount = 5;

    // Upper bound on accepted token length (characters). ~20x the largest expected
    // token (encrypted ≈ 6.5 KB), so legitimate tokens are never affected; it exists
    // only to cap pre-verification work on adversarial oversized input.
    private const int MaxTokenLength = 128 * 1024;

    // -- Observability -------------------------------------------------------
    // Emitted via System.Diagnostics.Metrics so consumers can wire OpenTelemetry
    // (or any IMeterListener) without the library taking a telemetry dependency.
    // The meter NAME is stable API; treat it as part of the contract. The failure
    // `reason` tag is a closed, bounded-cardinality vocabulary derived from the
    // strongly-typed PqJwtFailureReason — never the token, claims, or key material.
    private static readonly string MeterVersion = ResolveMeterVersion();

    private static readonly Meter Meter = new("PostQuantum.Jwt", MeterVersion);

    private static readonly Counter<long> ValidationsTotal =
        Meter.CreateCounter<long>(
            "pqjwt.validations",
            unit: "{validation}",
            description: "Total token validations, tagged outcome=success|failure (and reason on failure).");

    private readonly PqJwtValidationParameters _parameters;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a validator.</summary>
    /// <param name="parameters">Validation configuration.</param>
    /// <param name="timeProvider">Clock used for lifetime checks; defaults to <see cref="TimeProvider.System"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Neither <see cref="PqJwtValidationParameters.SignatureVerificationKey"/> nor
    /// <see cref="PqJwtValidationParameters.SignatureKeyResolver"/> is configured,
    /// or <see cref="PqJwtValidationParameters.RequireReplayProtection"/> is
    /// <see langword="true"/> while <see cref="PqJwtValidationParameters.ReplayCache"/>
    /// is <see langword="null"/>. A security validator without a way to obtain a
    /// verification key — or one whose replay-protection requirement is asserted
    /// but unwired — is misconfigured by definition; rejecting that at
    /// construction time means the misconfiguration surfaces before the first
    /// token arrives.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <see cref="PqJwtValidationParameters.ClockSkew"/> is negative — negative skew
    /// is rejected up front so time-validation behaviour is never harder to reason
    /// about than the documented contract.
    /// </exception>
    public PqJwtValidator(PqJwtValidationParameters parameters, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        if (parameters.SignatureVerificationKey is null && parameters.SignatureKeyResolver is null)
        {
            throw new ArgumentException(
                "PqJwtValidationParameters requires SignatureVerificationKey or SignatureKeyResolver.",
                nameof(parameters));
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(parameters.ClockSkew, TimeSpan.Zero);

        if (parameters.RequireReplayProtection && parameters.ReplayCache is null)
        {
            throw new ArgumentException(
                "PqJwtValidationParameters.RequireReplayProtection is set, but no ReplayCache was supplied. " +
                "Either provide a ReplayCache or clear RequireReplayProtection.",
                nameof(parameters));
        }

        _parameters = parameters;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Validates a compact token and returns its claims.</summary>
    /// <param name="token">The compact-serialized token.</param>
    /// <returns>The validated result.</returns>
    /// <exception cref="PqJwtValidationException">The token failed any validation check, including those caused by malformed Base64, malformed JSON, or malformed key material in the token's payload.</exception>
    /// <exception cref="PqJwtException">The validator is misconfigured for this token (e.g. an encrypted token arrived but no decryption key was supplied).</exception>
    public PqJwtValidationResult Validate(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        // Reject absurdly large tokens up front — before any split, Base64Url decode,
        // JSON parse, or (expensive) ML-DSA verification touches the input. A signed
        // token is ~4.5 KB and an encrypted one ~6.5 KB; the cap is generously above
        // any legitimate token, so this only stops a memory/CPU-exhaustion attempt
        // (a multi-megabyte "token") from amplifying work the signature check would
        // reject anyway.
        if (token.Length > MaxTokenLength)
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.MalformedToken,
                $"Token exceeds the maximum accepted length of {MaxTokenLength} characters.");
        }

        try
        {
            var parts = token.Split('.');
            var result = parts.Length switch
            {
                SignedPartCount => ValidateSigned(parts, wasEncrypted: false),
                EncryptedPartCount => ValidateEncrypted(parts),
                _ => throw new PqJwtValidationException(
                    PqJwtFailureReason.MalformedToken,
                    $"Malformed token: expected {SignedPartCount} or {EncryptedPartCount} segments, got {parts.Length}."),
            };

            // Reached only after every check has passed (fail-closed: we never
            // arrive here on a rejected token).
            ValidationsTotal.Add(1, new KeyValuePair<string, object?>("outcome", "success"));
            return result;
        }
        catch (PqJwtException ex)
        {
            // PqJwtException and its subclass PqJwtValidationException are the
            // documented fail-closed types — pass through unchanged, but record
            // the failure first. A PqJwtValidationException carries its own typed
            // Reason; a plain PqJwtException is operator misconfiguration.
            RecordFailure(ex);
            throw;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or JsonException)
        {
            // Known leak families from deeper layers: Base64 parsing
            // (FormatException), JSON parsing (System.Text.Json.JsonException),
            // and primitive crypto material checks (CryptographicException).
            // Adversarial inputs can drive any of these out of the validator;
            // the fail-closed contract says "every validation failure becomes
            // PqJwtValidationException" — so we wrap them with the original as
            // inner exception, deriving the reason from the leaked type (not its
            // message), and record the failure before rethrowing.
            var reason = ex switch
            {
                FormatException => PqJwtFailureReason.MalformedEncoding,
                JsonException => PqJwtFailureReason.MalformedJson,
                _ => PqJwtFailureReason.CryptographicMaterial, // CryptographicException
            };
            RecordFailureTag(ReasonTag(reason));
            throw new PqJwtValidationException(
                reason,
                "Token failed validation due to malformed structure or invalid cryptographic material.",
                ex);
        }
    }

    private PqJwtValidationResult ValidateEncrypted(string[] parts)
    {
        if (_parameters.DecryptionKey is null)
        {
            throw new PqJwtException(
                "Token is encrypted but PqJwtValidationParameters.DecryptionKey was not supplied.");
        }

        var header = JoseHeader.Parse(Base64Url.DecodeToUtf8(parts[0]));
        if (!string.Equals(header.Algorithm, PqJwtAlgorithms.XWing, StringComparison.Ordinal))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.AlgorithmNotAccepted,
                $"Unsupported key-agreement algorithm '{Sanitize(header.Algorithm)}'; expected '{PqJwtAlgorithms.XWing}'.");
        }

        if (!string.Equals(header.Encryption, PqJwtAlgorithms.Aes256Gcm, StringComparison.Ordinal))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.AlgorithmNotAccepted,
                $"Unsupported content-encryption algorithm '{Sanitize(header.Encryption)}'; expected '{PqJwtAlgorithms.Aes256Gcm}'.");
        }

        // The builder always emits cty=JWT for encrypted (nested) tokens; require it on
        // the validator side too so a producer can't ship an encrypted blob that
        // *happens* to decrypt to something signed-JWT-shaped but was labelled as some
        // other content type.
        if (!string.Equals(header.ContentType, PqJwtAlgorithms.TokenType, StringComparison.Ordinal))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.InvalidHeader,
                $"Encrypted token must declare 'cty' = '{PqJwtAlgorithms.TokenType}'; got '{Sanitize(header.ContentType)}'.");
        }

        var innerJws = Decrypt(parts, header, _parameters.DecryptionKey);

        // The decrypted content is itself a signed JWT; validate it fully.
        var innerParts = innerJws.Split('.');
        if (innerParts.Length != SignedPartCount)
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.InnerNotSigned, "Decrypted content is not a signed JWT.");
        }

        return ValidateSigned(innerParts, wasEncrypted: true);
    }

    private static string Decrypt(string[] parts, JoseHeader header, XWingPrivateKey decryptionKey)
    {
        byte[] sharedSecret;
        try
        {
            sharedSecret = XWing.Decapsulate(decryptionKey, Base64Url.Decode(parts[1]));
        }
        catch (Exception ex) when (ex is FormatException or PqJwtException)
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.KeyAgreementMalformed, "Token key-agreement material is malformed.", ex);
        }

        byte[]? plaintext = null;
        try
        {
            var nonce = Base64Url.Decode(parts[2]);
            var ciphertext = Base64Url.Decode(parts[3]);
            var tag = Base64Url.Decode(parts[4]);
            var aad = Encoding.ASCII.GetBytes(parts[0]);
            plaintext = new byte[ciphertext.Length];

            using (var gcm = new AesGcm(sharedSecret, tag.Length))
            {
                gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            }

            // The decoded string still lives in managed memory beyond our control,
            // but zeroing the intermediate byte buffer shortens one plaintext
            // copy's lifetime to a few microseconds — consistent with the rest of
            // the project's key-material hygiene discipline.
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            // A bad tag, tampered ciphertext, or wrong key all land here. Fail closed.
            throw new PqJwtValidationException(
                PqJwtFailureReason.DecryptionFailed, "Token decryption failed (authentication tag mismatch).", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
            if (plaintext is not null)
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    private PqJwtValidationResult ValidateSigned(string[] parts, bool wasEncrypted)
    {
        var header = JoseHeader.Parse(Base64Url.DecodeToUtf8(parts[0]));
        if (!string.Equals(header.Algorithm, PqJwtAlgorithms.MLDsa65, StringComparison.Ordinal))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.AlgorithmNotAccepted,
                $"Unsupported or disallowed signature algorithm '{Sanitize(header.Algorithm)}'; expected '{PqJwtAlgorithms.MLDsa65}'.");
        }

        var verificationKey = ResolveVerificationKey(header.KeyId);
        VerifySignature(parts, verificationKey);

        var claims = ParseClaims(parts[1]);
        ValidateClaims(claims);
        EnforceReplayPolicy(claims);
        return new PqJwtValidationResult(claims, wasEncrypted);
    }

    private MLDsa ResolveVerificationKey(string? keyId)
    {
        // The constructor already guarantees at least one of these is set.
        if (_parameters.SignatureKeyResolver is { } resolver)
        {
            return resolver(keyId)
                ?? throw new PqJwtValidationException(
                    PqJwtFailureReason.UnknownKeyId,
                    $"No verification key was resolved for kid '{Sanitize(keyId)}'.");
        }

        return _parameters.SignatureVerificationKey!;
    }

    private void EnforceReplayPolicy(Dictionary<string, JsonElement> claims)
    {
        if (_parameters.ReplayCache is not { } cache)
        {
            return;
        }

        var jwtId = claims.TryGetValue("jti", out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

        if (string.IsNullOrEmpty(jwtId))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.MissingJwtId, "Replay protection is enabled but the token has no 'jti' claim.");
        }

        // Replay protection requires a usable expiry: the cache entry must be able
        // to expire, or the cache grows without bound. So an absent or malformed exp
        // is rejected here (independently of ValidateLifetime, which the caller may
        // have disabled). A one-time-use token without an expiry is nonsensical
        // anyway — replay protection is for short-lived tokens.
        DateTimeOffset expiresAt;
        switch (GetUnixTime(claims, "exp", out var exp))
        {
            case TimeClaim.Present:
                expiresAt = exp;
                break;
            case TimeClaim.Malformed:
                throw new PqJwtValidationException(
                    PqJwtFailureReason.MalformedTimeClaim, "Token 'exp' claim is not an integer Unix time.");
            default: // Absent
                throw new PqJwtValidationException(
                    PqJwtFailureReason.MissingExpiration,
                    "Replay protection requires an 'exp' claim so the replay-cache entry can expire; this token has none.");
        }

        if (!cache.TryRegister(jwtId, expiresAt))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.ReplayDetected, $"Token replay detected for jti '{Sanitize(jwtId)}'.");
        }
    }

    private static void VerifySignature(string[] parts, MLDsa verificationKey)
    {
        byte[] signature;
        try
        {
            signature = Base64Url.Decode(parts[2]);
        }
        catch (FormatException ex)
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.SignatureMalformed, "Token signature is not valid base64url.", ex);
        }

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        if (!verificationKey.VerifyData(signingInput, signature))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.SignatureMismatch, "Token signature verification failed.");
        }
    }

    private static Dictionary<string, JsonElement> ParseClaims(string encodedPayload)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(Base64Url.Decode(encodedPayload));
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.MalformedJson, "Token payload is not valid JSON.", ex);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new PqJwtValidationException(
                    PqJwtFailureReason.MalformedPayload, "Token payload is not a JSON object.");
            }

            var claims = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                claims[property.Name] = property.Value.Clone();
            }

            return claims;
        }
    }

    private void ValidateClaims(Dictionary<string, JsonElement> claims)
    {
        ValidateLifetime(claims);
        ValidateIssuer(claims);
        ValidateAudience(claims);
    }

    private void ValidateLifetime(Dictionary<string, JsonElement> claims)
    {
        if (!_parameters.ValidateLifetime)
        {
            return;
        }

        var now = _timeProvider.GetUtcNow();
        var skew = _parameters.ClockSkew;

        switch (GetUnixTime(claims, "exp", out var exp))
        {
            case TimeClaim.Present:
                if (now > exp + skew)
                {
                    throw new PqJwtValidationException(
                        PqJwtFailureReason.Expired, $"Token expired at {exp:O}.");
                }

                break;
            case TimeClaim.Malformed:
                throw new PqJwtValidationException(
                    PqJwtFailureReason.MalformedTimeClaim, "Token 'exp' claim is not an integer Unix time.");
            case TimeClaim.Absent:
                if (_parameters.RequireExpiration)
                {
                    throw new PqJwtValidationException(
                        PqJwtFailureReason.MissingExpiration, "Token is missing the required 'exp' claim.");
                }

                break;
        }

        switch (GetUnixTime(claims, "nbf", out var nbf))
        {
            case TimeClaim.Present:
                if (now < nbf - skew)
                {
                    throw new PqJwtValidationException(
                        PqJwtFailureReason.NotYetValid, $"Token is not valid before {nbf:O}.");
                }

                break;
            case TimeClaim.Malformed:
                throw new PqJwtValidationException(
                    PqJwtFailureReason.MalformedTimeClaim, "Token 'nbf' claim is not an integer Unix time.");
            case TimeClaim.Absent:
                break;
        }
    }

    private void ValidateIssuer(Dictionary<string, JsonElement> claims)
    {
        if (_parameters.ValidIssuer is null)
        {
            return;
        }

        var issuer = claims.TryGetValue("iss", out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

        if (!string.Equals(issuer, _parameters.ValidIssuer, StringComparison.Ordinal))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.IssuerMismatch,
                $"Token issuer '{Sanitize(issuer)}' does not match the expected issuer.");
        }
    }

    private void ValidateAudience(Dictionary<string, JsonElement> claims)
    {
        if (_parameters.ValidAudience is null)
        {
            return;
        }

        if (!claims.TryGetValue("aud", out var aud) || !AudienceContains(aud, _parameters.ValidAudience))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.AudienceMismatch, "Token audience does not include the expected audience.");
        }
    }

    private static bool AudienceContains(JsonElement audience, string expected)
    {
        switch (audience.ValueKind)
        {
            case JsonValueKind.String:
                return string.Equals(audience.GetString(), expected, StringComparison.Ordinal);
            case JsonValueKind.Array:
                foreach (var item in audience.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String &&
                        string.Equals(item.GetString(), expected, StringComparison.Ordinal))
                    {
                        return true;
                    }
                }

                return false;
            default:
                return false;
        }
    }

    private enum TimeClaim
    {
        Absent,     // the claim is not present
        Malformed,  // present, but not an integer Unix time (string, fraction, array, …)
        Present,    // present and a valid integer Unix time
    }

    // Tri-state so callers can distinguish "absent" from "present but malformed".
    // A present-but-malformed exp/nbf must be REJECTED (fail-closed), never silently
    // treated as absent — otherwise a malformed exp becomes an immortal token and a
    // malformed nbf bypasses the not-before check.
    private static TimeClaim GetUnixTime(
        Dictionary<string, JsonElement> claims, string name, out DateTimeOffset value)
    {
        value = default;
        if (!claims.TryGetValue(name, out var element))
        {
            return TimeClaim.Absent;
        }

        // Must be an integer Unix-seconds value AND within the range DateTimeOffset
        // can represent. A fractional number, a string, or an in-Int64-but-out-of-
        // DateTimeOffset-range value (e.g. a huge exp) is Malformed — never let
        // FromUnixTimeSeconds throw ArgumentOutOfRangeException out of the validator.
        if (element.ValueKind == JsonValueKind.Number &&
            element.TryGetInt64(out var seconds) &&
            seconds is >= UnixSecondsMin and <= UnixSecondsMax)
        {
            value = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return TimeClaim.Present;
        }

        return TimeClaim.Malformed;
    }

    // Inclusive bounds of DateTimeOffset expressed as Unix seconds
    // (DateTimeOffset.MinValue / MaxValue .ToUnixTimeSeconds()).
    private const long UnixSecondsMin = -62135596800L;
    private const long UnixSecondsMax = 253402300799L;

    // Renders an untrusted, token-derived value (a header alg/kid, or a claim like
    // iss/jti) safe to embed in an exception message. Control characters are
    // replaced — so a crafted value can't forge log lines (CRLF log injection) when
    // a consumer logs the exception — and the length is capped to avoid log
    // flooding. Several of these values (e.g. the header alg/kid) are read BEFORE
    // signature verification, so they are fully attacker-controlled.
    private const int MaxEmbeddedValueLength = 64;

    private static string Sanitize(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "<missing>";
        }

        var length = Math.Min(value.Length, MaxEmbeddedValueLength);
        var builder = new StringBuilder(length + 1);
        foreach (var c in value.AsSpan(0, length))
        {
            builder.Append(char.IsControl(c) ? '�' : c);
        }

        if (value.Length > MaxEmbeddedValueLength)
        {
            builder.Append('…');
        }

        return builder.ToString();
    }

    // Records a fail-closed rejection on the metric. A PqJwtValidationException
    // carries its own strongly-typed Reason (set at the throw site); a plain
    // PqJwtException is operator misconfiguration, not a token-level rejection.
    private static void RecordFailure(PqJwtException ex) =>
        RecordFailureTag(ex is PqJwtValidationException v ? ReasonTag(v.Reason) : "misconfigured");

    private static void RecordFailureTag(string reasonTag) =>
        ValidationsTotal.Add(
            1,
            new KeyValuePair<string, object?>("outcome", "failure"),
            new KeyValuePair<string, object?>("reason", reasonTag));

    // Maps the typed reason to a stable, snake_case metric tag. Switching over the
    // enum (not parsing a message) means a new reason that forgets a tag is a
    // compile-visible omission the PqJwtMetricsTests completeness test also locks.
    internal static string ReasonTag(PqJwtFailureReason reason) => reason switch
    {
        PqJwtFailureReason.MalformedToken => "malformed_token",
        PqJwtFailureReason.MalformedEncoding => "malformed_encoding",
        PqJwtFailureReason.MalformedJson => "malformed_json",
        PqJwtFailureReason.MalformedPayload => "malformed_payload",
        PqJwtFailureReason.InvalidHeader => "invalid_header",
        PqJwtFailureReason.AlgorithmNotAccepted => "algorithm_not_accepted",
        PqJwtFailureReason.SignatureMalformed => "signature_malformed",
        PqJwtFailureReason.SignatureMismatch => "signature_mismatch",
        PqJwtFailureReason.UnknownKeyId => "unknown_kid",
        PqJwtFailureReason.KeyAgreementMalformed => "key_agreement_malformed",
        PqJwtFailureReason.DecryptionFailed => "decryption_failed",
        PqJwtFailureReason.InnerNotSigned => "inner_not_signed",
        PqJwtFailureReason.MalformedTimeClaim => "malformed_time_claim",
        PqJwtFailureReason.Expired => "expired",
        PqJwtFailureReason.NotYetValid => "not_yet_valid",
        PqJwtFailureReason.MissingExpiration => "missing_exp",
        PqJwtFailureReason.IssuerMismatch => "issuer_mismatch",
        PqJwtFailureReason.AudienceMismatch => "audience_mismatch",
        PqJwtFailureReason.MissingJwtId => "missing_jti",
        PqJwtFailureReason.ReplayDetected => "replay_detected",
        PqJwtFailureReason.CryptographicMaterial => "crypto_material",
        _ => "other",
    };

    // The meter version tracks the package version (AssemblyInformationalVersion,
    // minus any +build-metadata suffix SourceLink appends).
    private static string ResolveMeterVersion()
    {
        var info = typeof(PqJwtValidator).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrEmpty(info))
        {
            return typeof(PqJwtValidator).Assembly.GetName().Version?.ToString() ?? "unknown";
        }

        var plus = info.IndexOf('+', StringComparison.Ordinal);
        return plus >= 0 ? info[..plus] : info;
    }
}
