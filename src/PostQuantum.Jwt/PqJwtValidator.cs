using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Internal;

namespace PostQuantum.Jwt;

/// <summary>
/// Validates post-quantum hybrid JWTs. Fail-closed by design: any problem with
/// structure, decryption, signature, or claims raises
/// <see cref="PqJwtValidationException"/> rather than returning a degraded result.
/// </summary>
/// <remarks>Instances are immutable and safe to reuse across threads.</remarks>
public sealed class PqJwtValidator
{
    private const int SignedPartCount = 3;
    private const int EncryptedPartCount = 5;

    private readonly PqJwtValidationParameters _parameters;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a validator.</summary>
    /// <param name="parameters">Validation configuration.</param>
    /// <param name="timeProvider">Clock used for lifetime checks; defaults to <see cref="TimeProvider.System"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// Neither <see cref="PqJwtValidationParameters.SignatureVerificationKey"/> nor
    /// <see cref="PqJwtValidationParameters.SignatureKeyResolver"/> is configured.
    /// A security validator without a way to obtain a verification key is
    /// misconfigured by definition — rejecting that at construction time means
    /// misconfiguration surfaces before the first token arrives.
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
        _parameters = parameters;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Validates a compact token and returns its claims.</summary>
    /// <param name="token">The compact-serialized token.</param>
    /// <returns>The validated result.</returns>
    /// <exception cref="PqJwtValidationException">The token failed any validation check.</exception>
    /// <exception cref="PqJwtException">The validator is misconfigured for this token.</exception>
    public PqJwtValidationResult Validate(string token)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);

        var parts = token.Split('.');
        return parts.Length switch
        {
            SignedPartCount => ValidateSigned(parts, wasEncrypted: false),
            EncryptedPartCount => ValidateEncrypted(parts),
            _ => throw new PqJwtValidationException(
                $"Malformed token: expected {SignedPartCount} or {EncryptedPartCount} segments, got {parts.Length}."),
        };
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
                $"Unsupported key-agreement algorithm '{header.Algorithm}'; expected '{PqJwtAlgorithms.XWing}'.");
        }

        if (!string.Equals(header.Encryption, PqJwtAlgorithms.Aes256Gcm, StringComparison.Ordinal))
        {
            throw new PqJwtValidationException(
                $"Unsupported content-encryption algorithm '{header.Encryption}'; expected '{PqJwtAlgorithms.Aes256Gcm}'.");
        }

        // The builder always emits cty=JWT for encrypted (nested) tokens; require it on
        // the validator side too so a producer can't ship an encrypted blob that
        // *happens* to decrypt to something signed-JWT-shaped but was labelled as some
        // other content type.
        if (!string.Equals(header.ContentType, PqJwtAlgorithms.TokenType, StringComparison.Ordinal))
        {
            throw new PqJwtValidationException(
                $"Encrypted token must declare 'cty' = '{PqJwtAlgorithms.TokenType}'; got '{header.ContentType ?? "<missing>"}'.");
        }

        var innerJws = Decrypt(parts, header, _parameters.DecryptionKey);

        // The decrypted content is itself a signed JWT; validate it fully.
        var innerParts = innerJws.Split('.');
        if (innerParts.Length != SignedPartCount)
        {
            throw new PqJwtValidationException("Decrypted content is not a signed JWT.");
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
            throw new PqJwtValidationException("Token key-agreement material is malformed.", ex);
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
            throw new PqJwtValidationException("Token decryption failed (authentication tag mismatch).", ex);
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
                $"Unsupported or disallowed signature algorithm '{header.Algorithm}'; expected '{PqJwtAlgorithms.MLDsa65}'.");
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
                    $"No verification key was resolved for kid '{keyId}'.");
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
            throw new PqJwtValidationException("Replay protection is enabled but the token has no 'jti' claim.");
        }

        var expiresAt = TryGetUnixTime(claims, "exp", out var exp) ? exp : DateTimeOffset.MaxValue;
        if (!cache.TryRegister(jwtId, expiresAt))
        {
            throw new PqJwtValidationException($"Token replay detected for jti '{jwtId}'.");
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
            throw new PqJwtValidationException("Token signature is not valid base64url.", ex);
        }

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        if (!verificationKey.VerifyData(signingInput, signature))
        {
            throw new PqJwtValidationException("Token signature verification failed.");
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
            throw new PqJwtValidationException("Token payload is not valid JSON.", ex);
        }

        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                throw new PqJwtValidationException("Token payload is not a JSON object.");
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

        if (TryGetUnixTime(claims, "exp", out var exp))
        {
            if (now > exp + skew)
            {
                throw new PqJwtValidationException($"Token expired at {exp:O}.");
            }
        }
        else if (_parameters.RequireExpiration)
        {
            throw new PqJwtValidationException("Token is missing the required 'exp' claim.");
        }

        if (TryGetUnixTime(claims, "nbf", out var nbf) && now < nbf - skew)
        {
            throw new PqJwtValidationException($"Token is not valid before {nbf:O}.");
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
                $"Token issuer '{issuer}' does not match the expected issuer.");
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
            throw new PqJwtValidationException("Token audience does not include the expected audience.");
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

    private static bool TryGetUnixTime(
        Dictionary<string, JsonElement> claims, string name, out DateTimeOffset value)
    {
        if (claims.TryGetValue(name, out var element) &&
            element.ValueKind == JsonValueKind.Number &&
            element.TryGetInt64(out var seconds))
        {
            value = DateTimeOffset.FromUnixTimeSeconds(seconds);
            return true;
        }

        value = default;
        return false;
    }
}
