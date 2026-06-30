using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Internal;

namespace PostQuantum.Jwt;

/// <summary>
/// Builds JOSE-style post-quantum tokens — ML-DSA-65 signatures with optional
/// hybrid X-Wing-style confidentiality — using secure, fail-closed defaults.
/// </summary>
/// <remarks>
/// <para>
/// Every token produced by this builder is signed with ML-DSA-65 — signing is
/// mandatory, there is no "alg: none" path. When a recipient encryption key is
/// supplied via <see cref="EncryptFor"/>, the signed token is additionally
/// wrapped with X-Wing key agreement and AES-256-GCM ("sign-then-encrypt").
/// </para>
/// <para>Instances are not thread-safe; build one token per builder.</para>
/// </remarks>
public sealed class PqJwtBuilder
{
    private readonly JsonObject _claims = [];
    private readonly TimeProvider _timeProvider;
    private MLDsa? _signingKey;
    private XWingPublicKey? _recipient;
    private string? _keyId;

    /// <summary>Creates a new builder.</summary>
    /// <param name="timeProvider">
    /// Clock used for <c>iat</c> and relative lifetimes. Defaults to
    /// <see cref="TimeProvider.System"/>; inject a fake clock in tests.
    /// </param>
    public PqJwtBuilder(TimeProvider? timeProvider = null) =>
        _timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>Sets the <c>iss</c> (issuer) claim.</summary>
    /// <param name="issuer">The issuer identifier.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder WithIssuer(string issuer) => SetStringClaim("iss", issuer);

    /// <summary>Sets the <c>sub</c> (subject) claim.</summary>
    /// <param name="subject">The subject identifier.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder WithSubject(string subject) => SetStringClaim("sub", subject);

    /// <summary>Sets the <c>aud</c> (audience) claim.</summary>
    /// <param name="audience">The audience identifier.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder WithAudience(string audience) => SetStringClaim("aud", audience);

    /// <summary>Sets the <c>jti</c> (JWT ID) claim.</summary>
    /// <param name="jwtId">A unique token identifier.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder WithJwtId(string jwtId) => SetStringClaim("jti", jwtId);

    /// <summary>Sets the <c>exp</c> (expiration) claim to an absolute time.</summary>
    /// <param name="expiresAt">When the token expires.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder WithExpiration(DateTimeOffset expiresAt) =>
        SetInt64Claim("exp", expiresAt.ToUnixTimeSeconds());

    /// <summary>Sets <c>iat</c> to now and <c>exp</c> to now plus <paramref name="lifetime"/>.</summary>
    /// <param name="lifetime">How long the token should remain valid.</param>
    /// <returns>This builder.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The lifetime is not positive.</exception>
    public PqJwtBuilder WithLifetime(TimeSpan lifetime)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);
        var now = _timeProvider.GetUtcNow();
        SetInt64Claim("iat", now.ToUnixTimeSeconds());
        return WithExpiration(now + lifetime);
    }

    /// <summary>Sets the <c>nbf</c> (not-before) claim.</summary>
    /// <param name="notBefore">The earliest time the token is valid.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder WithNotBefore(DateTimeOffset notBefore) =>
        SetInt64Claim("nbf", notBefore.ToUnixTimeSeconds());

    // AOT-safe primitive setters used by the convenience methods above.
    // They bypass JsonSerializer.SerializeToNode (which is reflection-based)
    // and construct JsonValue nodes directly.
    private PqJwtBuilder SetStringClaim(string name, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        _claims[name] = JsonValue.Create(value);
        return this;
    }

    private PqJwtBuilder SetInt64Claim(string name, long value)
    {
        _claims[name] = JsonValue.Create(value);
        return this;
    }

    /// <summary>Sets an arbitrary claim. Pass <c>null</c> to remove a previously set claim.</summary>
    /// <param name="name">The claim name.</param>
    /// <param name="value">The claim value (any JSON-serializable object), or <c>null</c> to remove it.</param>
    /// <returns>This builder.</returns>
    /// <remarks>
    /// This overload uses reflection-based JSON serialization, so it is
    /// <b>not</b> AOT/trim-safe. For trim-safe call sites use
    /// <c>WithClaim&lt;T&gt;(name, value, JsonTypeInfo&lt;T&gt;)</c> with a
    /// source-generated <c>JsonTypeInfo&lt;T&gt;</c>.
    /// </remarks>
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.SerializeToNode which may use reflection. Use WithClaim<T>(name, value, JsonTypeInfo<T>) in trimmed/AOT applications.")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.SerializeToNode which may generate code at runtime. Use WithClaim<T>(name, value, JsonTypeInfo<T>) in AOT applications.")]
    public PqJwtBuilder WithClaim(string name, object? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (value is null)
        {
            _claims.Remove(name);
        }
        else
        {
            _claims[name] = JsonSerializer.SerializeToNode(value);
        }

        return this;
    }

    /// <summary>
    /// Sets an arbitrary claim using a source-generated
    /// <c>JsonTypeInfo&lt;T&gt;</c>. AOT/trim-safe alternative to
    /// <see cref="WithClaim(string, object?)"/>.
    /// </summary>
    /// <typeparam name="T">The claim value's type.</typeparam>
    /// <param name="name">The claim name.</param>
    /// <param name="value">The claim value.</param>
    /// <param name="jsonTypeInfo">A source-generated type-info for <typeparamref name="T"/>.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder WithClaim<T>(string name, T value, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> jsonTypeInfo)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(jsonTypeInfo);
        var json = JsonSerializer.Serialize(value, jsonTypeInfo);
        _claims[name] = JsonNode.Parse(json);
        return this;
    }

    /// <summary>Signs the token with the given ML-DSA-65 private key. Required.</summary>
    /// <param name="signingKey">An ML-DSA private key (must be ML-DSA-65).</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder SignWith(MLDsa signingKey)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        if (signingKey.Algorithm != MLDsaAlgorithm.MLDsa65)
        {
            throw new PqJwtException(
                $"PostQuantum.Jwt signs with {PqJwtAlgorithms.MLDsa65}; got '{signingKey.Algorithm.Name}'.");
        }

        _signingKey = signingKey;
        return this;
    }

    /// <summary>Sets the <c>kid</c> (key ID) header for the signature.</summary>
    /// <param name="keyId">A key identifier the verifier can use to select a key.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder WithKeyId(string keyId)
    {
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        _keyId = keyId;
        return this;
    }

    /// <summary>
    /// Encrypts the signed token to the holder of <paramref name="recipient"/> using
    /// X-Wing + AES-256-GCM. Optional; when omitted, a signed (but not encrypted) token is produced.
    /// </summary>
    /// <param name="recipient">The recipient's X-Wing public key.</param>
    /// <returns>This builder.</returns>
    public PqJwtBuilder EncryptFor(XWingPublicKey recipient)
    {
        ArgumentNullException.ThrowIfNull(recipient);
        _recipient = recipient;
        return this;
    }

    /// <summary>Produces the compact-serialized token string.</summary>
    /// <returns>A signed (3-part) or signed-then-encrypted (5-part) compact token.</returns>
    /// <exception cref="PqJwtException">No signing key was supplied.</exception>
    public string Build()
    {
        if (_signingKey is null)
        {
            throw new PqJwtException("A signing key is required. Call SignWith(...) before Build().");
        }

        var signed = BuildSignedToken(_signingKey);
        return _recipient is null ? signed : EncryptToken(signed, _recipient);
    }

    private string BuildSignedToken(MLDsa signingKey)
    {
        var header = new JsonObject
        {
            ["alg"] = PqJwtAlgorithms.MLDsa65,
            ["typ"] = PqJwtAlgorithms.TokenType,
        };
        if (_keyId is not null)
        {
            header["kid"] = _keyId;
        }

        var encodedHeader = Base64Url.EncodeUtf8(header.ToJsonString());
        var encodedPayload = Base64Url.EncodeUtf8(_claims.ToJsonString());
        var signingInput = $"{encodedHeader}.{encodedPayload}";

        var signature = signingKey.SignData(Encoding.ASCII.GetBytes(signingInput));
        return $"{signingInput}.{Base64Url.Encode(signature)}";
    }

    private static string EncryptToken(string innerJws, XWingPublicKey recipient)
    {
        var header = new JsonObject
        {
            ["alg"] = PqJwtAlgorithms.XWing,
            ["enc"] = PqJwtAlgorithms.Aes256Gcm,
            ["typ"] = PqJwtAlgorithms.TokenType,
            ["cty"] = PqJwtAlgorithms.TokenType, // content is a nested JWT
        };
        var encodedHeader = Base64Url.EncodeUtf8(header.ToJsonString());

        var (sharedSecret, kemCiphertext) = XWing.Encapsulate(recipient);
        // The plaintext is the inner JWS — it carries the claims. Materialise it
        // before the try so the finally can zero it on the success path AND on any
        // exception out of AesGcm.Encrypt alike (CLAUDE.md: "zero key material …
        // after use"; we extend the same discipline to the sensitive plaintext).
        var plaintext = Encoding.UTF8.GetBytes(innerJws);
        try
        {
            // AAD binds the ciphertext to the protected header (RFC 7516 §5.1).
            var aad = Encoding.ASCII.GetBytes(encodedHeader);
            var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            using (var gcm = new AesGcm(sharedSecret, tag.Length))
            {
                gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            }

            return string.Join('.',
                encodedHeader,
                Base64Url.Encode(kemCiphertext),
                Base64Url.Encode(nonce),
                Base64Url.Encode(ciphertext),
                Base64Url.Encode(tag));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }
}
