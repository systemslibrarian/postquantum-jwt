using System.Collections.Concurrent;

namespace PostQuantum.Jwt;

/// <summary>
/// A simple, thread-safe, in-process <see cref="IPqJwtReplayCache"/> backed by a
/// concurrent dictionary keyed on <c>jti</c>. Expired entries are pruned lazily.
/// </summary>
/// <remarks>
/// Suitable for a single process. It does <b>not</b> coordinate across machines or
/// survive a restart; for distributed replay protection, implement
/// <see cref="IPqJwtReplayCache"/> over a shared store (e.g. Redis).
/// </remarks>
public sealed class InMemoryReplayCache : IPqJwtReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates a new in-memory replay cache.</summary>
    /// <param name="timeProvider">Clock used to expire entries; defaults to <see cref="TimeProvider.System"/>.</param>
    public InMemoryReplayCache(TimeProvider? timeProvider = null) =>
        _timeProvider = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public bool TryRegister(string jwtId, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwtId);

        Prune();

        // AddOrUpdate lets us treat a stale (already-expired) entry as reusable.
        var now = _timeProvider.GetUtcNow();
        var registered = true;
        _seen.AddOrUpdate(
            jwtId,
            expiresAt,
            (_, existing) =>
            {
                if (existing > now)
                {
                    registered = false; // still live → genuine replay
                    return existing;
                }

                return expiresAt; // previous entry already expired → allow reuse
            });

        return registered;
    }

    private void Prune()
    {
        var now = _timeProvider.GetUtcNow();
        foreach (var entry in _seen)
        {
            if (entry.Value <= now)
            {
                _seen.TryRemove(entry.Key, out _);
            }
        }
    }
}
