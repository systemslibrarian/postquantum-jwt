using System.Security.Cryptography;
using PostQuantum.Jwt.Cryptography;

namespace PostQuantum.Jwt;

/// <summary>
/// Configures how <see cref="PqJwtValidator"/> validates a token. Defaults are
/// strict and fail-closed: lifetime checks are on, expiration is required, and
/// the clock skew allowance is small.
/// </summary>
public sealed class PqJwtValidationParameters
{
    /// <summary>
    /// The ML-DSA-65 public key used to verify the token signature. Required
    /// unless <see cref="SignatureKeyResolver"/> is supplied; validation always
    /// fails closed if no key can be obtained.
    /// </summary>
    public MLDsa? SignatureVerificationKey { get; init; }

    /// <summary>
    /// Resolves a verification key from the token's <c>kid</c> header — enabling
    /// key rotation and multi-key validation. When set, it takes precedence over
    /// <see cref="SignatureVerificationKey"/>; returning <see langword="null"/>
    /// (unknown <c>kid</c>) fails validation closed.
    /// </summary>
    public Func<string?, MLDsa?>? SignatureKeyResolver { get; init; }

    /// <summary>
    /// Optional replay-detection hook keyed on <c>jti</c>. When set, a token must
    /// carry a <c>jti</c> and must not have been seen before, or validation fails.
    /// <para>
    /// <b>When unset, replay protection is OFF.</b> Tokens carrying a <c>jti</c>
    /// are accepted but never registered, so the same token may be replayed
    /// indefinitely. This is the documented default for the no-replay use
    /// case. Set <see cref="RequireReplayProtection"/> = <see langword="true"/>
    /// to fail-closed at validator construction when no cache is supplied —
    /// recommended for any deployment where forgetting to wire a cache would
    /// be a security regression.
    /// </para>
    /// </summary>
    public IPqJwtReplayCache? ReplayCache { get; init; }

    /// <summary>
    /// When <see langword="true"/>, the <see cref="PqJwtValidator"/> constructor
    /// throws <see cref="ArgumentException"/> if <see cref="ReplayCache"/> is
    /// <see langword="null"/>. Defaults to <see langword="false"/>, preserving
    /// the historical opt-in default — but turning it on means an operator who
    /// forgets to wire a cache sees the misconfiguration at startup rather
    /// than as a silent missing defense at runtime.
    /// </summary>
    public bool RequireReplayProtection { get; init; }

    /// <summary>
    /// The X-Wing private key used to decrypt encrypted (5-part) tokens. Required
    /// only when validating encrypted tokens; ignored for signed-only tokens.
    /// </summary>
    public XWingPrivateKey? DecryptionKey { get; init; }

    /// <summary>If set, the token's <c>iss</c> claim must equal this value.</summary>
    public string? ValidIssuer { get; init; }

    /// <summary>If set, the token's <c>aud</c> claim must contain this value.</summary>
    public string? ValidAudience { get; init; }

    /// <summary>
    /// Whether to enforce <c>exp</c> / <c>nbf</c>. Defaults to <see langword="true"/>.
    /// When set to <see langword="false"/>, lifetime checks (including
    /// <see cref="RequireExpiration"/>) are skipped entirely.
    /// </summary>
    public bool ValidateLifetime { get; init; } = true;

    /// <summary>
    /// Whether a token must carry an <c>exp</c> claim. Defaults to <see langword="true"/>;
    /// a token without an expiry is rejected. Has no effect when
    /// <see cref="ValidateLifetime"/> is <see langword="false"/>.
    /// </summary>
    public bool RequireExpiration { get; init; } = true;

    /// <summary>
    /// Tolerance applied to <c>exp</c> / <c>nbf</c> comparisons to absorb clock
    /// differences between issuer and validator. Defaults to 60 seconds. The value
    /// must be non-negative; the <see cref="PqJwtValidator"/> constructor rejects
    /// a negative skew.
    /// </summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromSeconds(60);
}
