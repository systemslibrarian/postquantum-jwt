namespace PostQuantum.Jwt;

/// <summary>
/// A hook for detecting replayed tokens by their <c>jti</c> (JWT ID) claim. When
/// a cache is supplied on <see cref="PqJwtValidationParameters.ReplayCache"/>, the
/// validator rejects any token whose <c>jti</c> has already been seen — and
/// rejects tokens that lack a <c>jti</c> entirely.
/// </summary>
/// <remarks>
/// Implementations must be safe for concurrent use. Replay protection is only as
/// strong as the cache: an in-process cache does not coordinate across instances,
/// so distributed deployments should back this with a shared store.
/// </remarks>
public interface IPqJwtReplayCache
{
    /// <summary>
    /// Atomically records a token's <c>jti</c> as seen, returning whether it was new.
    /// </summary>
    /// <param name="jwtId">The token's <c>jti</c> claim.</param>
    /// <param name="expiresAt">
    /// When the token expires, so the cache may evict the entry afterwards. Pass
    /// <see cref="DateTimeOffset.MaxValue"/> when the token has no expiry.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="jwtId"/> had not been seen (first use);
    /// <see langword="false"/> if it is a replay.
    /// </returns>
    bool TryRegister(string jwtId, DateTimeOffset expiresAt);
}
