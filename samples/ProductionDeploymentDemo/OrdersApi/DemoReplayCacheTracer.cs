using PostQuantum.Jwt;

namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.OrdersApi;

/// <summary>
/// DEMO-ONLY wrapper around an <see cref="IPqJwtReplayCache"/> that records
/// the wire-level replay op (key, TTL, accepted/duplicate) into a per-request
/// <see cref="AsyncLocal{T}"/> so a downstream middleware can surface it on
/// an <c>X-Replay-Op</c> response header for the browser-driven landing page
/// to render.
/// </summary>
/// <remarks>
/// Gated by the same <c>EXPOSE_FAILURE_REASON</c> env that opens up the
/// typed failure reason — production deployments leak neither. Without this
/// wrapper the Redis hop is invisible to a demo viewer, so the demo's most
/// distinctive feature (distributed replay protection on a real Redis,
/// not an in-memory simulation) is also invisible. With it, the viewer
/// sees the actual op the validator just performed against the cache.
/// </remarks>
public sealed class DemoReplayCacheTracer : IPqJwtReplayCache
{
    private static readonly AsyncLocal<string?> _lastOp = new();

    private readonly IPqJwtReplayCache _inner;
    private readonly string _backendLabel;
    private readonly TimeProvider _time;

    public DemoReplayCacheTracer(
        IPqJwtReplayCache inner,
        string backendLabel,
        TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        ArgumentException.ThrowIfNullOrEmpty(backendLabel);

        _inner = inner;
        _backendLabel = backendLabel;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>The op recorded by the most recent <see cref="TryRegister"/>
    /// call on the current async flow, or <c>null</c> if none ran (e.g., the
    /// token was rejected at signature verification before the replay check).</summary>
    public static string? CurrentLastOp => _lastOp.Value;

    public static void Clear() => _lastOp.Value = null;

    public bool TryRegister(string jwtId, DateTimeOffset expiresAt)
    {
        var accepted = _inner.TryRegister(jwtId, expiresAt);

        var ttl = expiresAt == DateTimeOffset.MaxValue
            ? "no TTL"
            : $"EX {(int)Math.Max(1, Math.Ceiling((expiresAt - _time.GetUtcNow()).TotalSeconds))}s";

        // Truncate jti so the header carries a fingerprint, not the full id.
        // The whole tracer is demo-gated; even so, prefer parsimony.
        var shortJti = jwtId.Length > 12 ? jwtId[..8] + "…" : jwtId;
        var verb = accepted ? "OK (new)" : "DUPLICATE";

        _lastOp.Value =
            $"{_backendLabel} SET NX pqjwt:production-demo:jti:{shortJti} {ttl} → {verb}";

        return accepted;
    }
}
