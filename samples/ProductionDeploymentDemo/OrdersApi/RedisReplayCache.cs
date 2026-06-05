using PostQuantum.Jwt;
using StackExchange.Redis;

namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.OrdersApi;

/// <summary>
/// Redis-backed replay cache using atomic SET NX with a TTL.
/// </summary>
public sealed class RedisReplayCache : IPqJwtReplayCache, IDisposable
{
    private readonly IConnectionMultiplexer _multiplexer;
    private readonly IDatabase _db;
    private readonly string _prefix;
    private readonly TimeProvider _time;
    private readonly bool _ownsConnection;

    public RedisReplayCache(
        IConnectionMultiplexer multiplexer,
        bool ownsConnection = false,
        string keyPrefix = "pqjwt:production-demo:jti:",
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(multiplexer);

        _multiplexer = multiplexer;
        _db = multiplexer.GetDatabase();
        _ownsConnection = ownsConnection;
        _prefix = keyPrefix;
        _time = timeProvider ?? TimeProvider.System;
    }

    public bool TryRegister(string jwtId, DateTimeOffset expiresAt)
    {
        ArgumentException.ThrowIfNullOrEmpty(jwtId);

        TimeSpan? ttl = expiresAt == DateTimeOffset.MaxValue
            ? null
            : Max(expiresAt - _time.GetUtcNow(), TimeSpan.FromSeconds(1));

        return _db.StringSet(
            _prefix + jwtId,
            value: "1",
            expiry: ttl,
            when: When.NotExists);
    }

    public void Dispose()
    {
        if (_ownsConnection)
        {
            _multiplexer.Dispose();
        }
    }

    private static TimeSpan Max(TimeSpan a, TimeSpan b) => a > b ? a : b;
}
