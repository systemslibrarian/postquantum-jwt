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
    // How often a full sweep for expired entries may run. Pruning is purely memory
    // hygiene — replay *correctness* never depends on it, because TryRegister already
    // treats an existing-but-expired entry as reusable. Throttling the sweep keeps
    // TryRegister amortized O(1) instead of O(n)-per-call: a flood of unique tokens
    // can no longer turn every registration into a full-dictionary scan.
    private static readonly long PruneIntervalTicks = TimeSpan.FromSeconds(30).Ticks;

    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private long _lastPruneTicks;

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

        // Run a full sweep at most once per PruneIntervalTicks. The first thread to
        // observe the interval has elapsed claims the slot via CompareExchange and
        // sweeps; concurrent callers skip and return immediately.
        var last = Interlocked.Read(ref _lastPruneTicks);
        if (now.UtcTicks - last < PruneIntervalTicks)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastPruneTicks, now.UtcTicks, last) != last)
        {
            return;
        }

        foreach (var entry in _seen)
        {
            if (entry.Value <= now)
            {
                _seen.TryRemove(entry.Key, out _);
            }
        }
    }
}
