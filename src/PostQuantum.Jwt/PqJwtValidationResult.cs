using System.Text.Json;

namespace PostQuantum.Jwt;

/// <summary>
/// The outcome of a successful validation. Instances are only ever returned when
/// every check passed; failures throw <see cref="PqJwtValidationException"/>.
/// </summary>
public sealed class PqJwtValidationResult
{
    internal PqJwtValidationResult(
        IReadOnlyDictionary<string, JsonElement> claims,
        bool wasEncrypted)
    {
        Claims = claims;
        WasEncrypted = wasEncrypted;
    }

    /// <summary>The validated claims, keyed by claim name.</summary>
    public IReadOnlyDictionary<string, JsonElement> Claims { get; }

    /// <summary>Whether the token was encrypted (X-Wing + AES-256-GCM) in addition to signed.</summary>
    public bool WasEncrypted { get; }

    /// <summary>The <c>iss</c> claim, if present.</summary>
    public string? Issuer => GetString("iss");

    /// <summary>The <c>sub</c> claim, if present.</summary>
    public string? Subject => GetString("sub");

    /// <summary>The <c>jti</c> claim, if present.</summary>
    public string? JwtId => GetString("jti");

    /// <summary>The <c>exp</c> claim as an absolute time, if present.</summary>
    public DateTimeOffset? ExpiresAt => GetUnixTime("exp");

    /// <summary>Gets a string claim, or <see langword="null"/> if absent or not a string.</summary>
    /// <param name="name">The claim name.</param>
    /// <returns>The claim value, or <see langword="null"/>.</returns>
    public string? GetString(string name) =>
        Claims.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    // Safe by construction: a non-integer or out-of-range time claim yields null
    // rather than throwing. A successful validation result must never throw when a
    // caller reads a standard property like ExpiresAt.
    private DateTimeOffset? GetUnixTime(string name) =>
        Claims.TryGetValue(name, out var value) &&
        value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt64(out var seconds) &&
        seconds is >= -62135596800L and <= 253402300799L
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
}
