// DistributedReplayCache
//
// InMemoryReplayCache (in the library) proves the jti-replay concept but is
// single-process: a token "replayed" on a different node is NOT detected. The
// moment you scale horizontally you need a SHARED store. This sample shows two
// implementations of IPqJwtReplayCache backed by a distributed cache.
//
// THE CRITICAL CONSTRAINT: IPqJwtReplayCache.TryRegister must be ATOMIC — it has
// to record-and-test in one indivisible step, or two nodes racing the same
// replayed token can both see "not present" and both accept it. A naive
// get-then-set has exactly that race and is WRONG for replay defense.
//
//   • RedisReplayCache (RECOMMENDED) uses Redis SET key value NX PX <ttl>, which
//     is atomic set-if-absent at the server — the correct primitive. Add the
//     StackExchange.Redis package to use it.
//
//   • DistributedCacheReplayCache uses IDistributedCache for portability across
//     providers, but IDistributedCache has no atomic set-if-absent, so it cannot
//     fully close the race on its own. It is acceptable only when your provider
//     guarantees atomic Set semantics or you accept a tiny race window. We
//     include it because Gemini-style "use IDistributedCache" is a common ask —
//     but we are honest that Redis SETNX is the right answer.
//
// To God be the glory - 1 Corinthians 10:31.

using Microsoft.Extensions.Caching.Distributed;
using PostQuantum.Jwt;
using StackExchange.Redis;

namespace PostQuantum.Jwt.Samples.DistributedReplayCache;

/// <summary>
/// RECOMMENDED distributed replay cache. Uses Redis <c>SET … NX PX</c> for a
/// genuinely atomic "register if absent", which is what replay defense requires
/// across multiple nodes.
/// </summary>
public sealed class RedisReplayCache : IPqJwtReplayCache
{
    private readonly IDatabase _db;
    private readonly string _prefix;
    private readonly TimeProvider _time;

    /// <param name="multiplexer">A shared <see cref="IConnectionMultiplexer"/> (register it as a singleton).</param>
    /// <param name="keyPrefix">Namespace for jti keys, so they don't collide with other Redis data.</param>
    /// <param name="timeProvider">Clock for computing TTL; defaults to system.</param>
    public RedisReplayCache(
        IConnectionMultiplexer multiplexer,
        string keyPrefix = "pqjwt:jti:",
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(multiplexer);
        _db = multiplexer.GetDatabase();
        _prefix = keyPrefix;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public bool TryRegister(string jwtId, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwtId);

        // TTL = time until the token expires (plus a small floor). Once the token
        // can no longer validate on its own merits, the jti entry is useless and
        // Redis evicts it automatically — the cache never grows without bound.
        TimeSpan? ttl = expiresAt == DateTimeOffset.MaxValue
            ? null
            : Max(expiresAt - _time.GetUtcNow(), TimeSpan.FromSeconds(1));

        // Atomic set-if-absent at the server. Returns true only if the key did
        // not already exist — i.e. this is the FIRST time we've seen this jti.
        // Two nodes racing the same jti: exactly one gets true.
        return _db.StringSet(
            _prefix + jwtId,
            value: "1",
            expiry: ttl,
            when: When.NotExists);
    }

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;
}

/// <summary>
/// Portable replay cache over <see cref="IDistributedCache"/> (Redis, SQL Server,
/// etc.). NOTE: <see cref="IDistributedCache"/> has no atomic set-if-absent, so
/// this cannot fully eliminate the race where two nodes register the same jti
/// simultaneously. Prefer <see cref="RedisReplayCache"/> for true atomicity; use
/// this only when provider portability outweighs that residual risk, or when
/// your store's Set is atomic.
/// </summary>
public sealed class DistributedCacheReplayCache : IPqJwtReplayCache
{
    private readonly IDistributedCache _cache;
    private readonly string _prefix;
    private readonly TimeProvider _time;
    private static readonly byte[] Marker = "1"u8.ToArray();

    public DistributedCacheReplayCache(
        IDistributedCache cache,
        string keyPrefix = "pqjwt:jti:",
        TimeProvider? timeProvider = null)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _prefix = keyPrefix;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// <b>SCALE WARNING.</b> IPqJwtReplayCache.TryRegister is synchronous, but
    /// IDistributedCache is fundamentally async — every <c>_cache.Get</c> and
    /// <c>_cache.Set</c> call below dispatches via .GetAwaiter().GetResult() on
    /// a thread-pool thread. Under heavy load that blocks on network I/O can
    /// starve the ASP.NET Core thread pool and degrade the entire host (the
    /// same anti-pattern that motivated <c>HttpPqJwtKeyRing</c>'s background-
    /// refresh refactor). This sample is fine for low-traffic services and
    /// for showing the IDistributedCache plug-shape, but it is NOT a
    /// horizontal-scale production primitive.
    /// </para>
    /// <para>
    /// <b>Use <see cref="RedisReplayCache"/> for production.</b> It calls
    /// StackExchange.Redis directly (synchronous client API, no
    /// sync-over-async), and uses <c>SET key value NX PX &lt;ttl&gt;</c> for
    /// atomic set-if-absent — closing both the thread-pool risk AND the
    /// get-then-set race at the same time. If you have a non-Redis provider,
    /// implement <c>IPqJwtReplayCache</c> directly against its native
    /// synchronous-friendly API rather than going through IDistributedCache.
    /// </para>
    /// </remarks>
    public bool TryRegister(string jwtId, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwtId);
        var key = _prefix + jwtId;

        // The interface is synchronous; IDistributedCache is async under the
        // hood. See the SCALE WARNING above — for production, RedisReplayCache.
        if (_cache.Get(key) is not null)
        {
            return false;   // already seen -> replay
        }

        var options = new DistributedCacheEntryOptions();
        if (expiresAt != DateTimeOffset.MaxValue)
        {
            var ttl = expiresAt - _time.GetUtcNow();
            options.AbsoluteExpirationRelativeToNow = ttl > TimeSpan.Zero ? ttl : TimeSpan.FromSeconds(1);
        }

        // RACE WINDOW between the Get above and this Set: two nodes can both pass
        // the Get and both Set. See the class summary — use RedisReplayCache to
        // close it. Kept here because the pattern is what people ask for.
        _cache.Set(key, Marker, options);
        return true;
    }
}
