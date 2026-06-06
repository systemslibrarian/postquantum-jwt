using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using PostQuantum.Jwt;

namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.OrdersApi;

/// <summary>
/// Demo HTTP key ring for issuer-published ML-DSA verification keys.
/// </summary>
/// <remarks>
/// This deliberately allows an HTTP endpoint only when the demo configuration
/// sets ALLOW_INSECURE_KEY_DIRECTORY=true. Production deployments should use
/// HTTPS/mTLS/service identity or signed config. The key directory is a trust root.
///
/// The important production-shaped behavior: key refresh happens in the
/// background. <see cref="Resolve"/> is a pure in-memory lookup used on the auth
/// request path; it never performs sync-over-async HTTP.
/// </remarks>
public sealed class IssuerKeyRing : IHostedService, IDisposable
{
    private readonly HttpClient _http;
    private readonly Uri _endpoint;
    private readonly TimeSpan _refreshInterval;
    private readonly ILogger<IssuerKeyRing> _logger;
    private readonly ConcurrentDictionary<string, MLDsa> _cache = new(StringComparer.Ordinal);
    // Parallel record of the base64 each kid was last imported from. The
    // background refresh runs every ~5s; the JWKS payload almost never changes
    // between polls. Without this short-circuit we would re-import a fresh
    // native MLDsa handle on every refresh (6 churned-and-quarantined handles
    // per kid per minute under steady state), pushing all of them through the
    // 30s deferred-disposal queue. Comparing the published base64 to what we
    // imported it from lets us skip the reimport when the key is unchanged.
    private readonly ConcurrentDictionary<string, string> _cachedKeyBase64 = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    // Native MLDsa handles whose cache slot has been replaced or evicted. We
    // do NOT dispose them inline because a concurrent Resolve() may still
    // hold the reference returned from TryGetValue and be mid-VerifyData on
    // its native pointer. Disposal happens here after a TTL that's >>
    // the longest realistic verify time (which is ~100 µs). Drained on every
    // RefreshNowAsync call.
    private readonly ConcurrentQueue<(DateTimeOffset QuarantinedAt, MLDsa Key, string Kid)> _quarantine = new();
    private static readonly TimeSpan QuarantineTtl = TimeSpan.FromSeconds(30);

    private CancellationTokenSource? _refreshCts;
    private Task? _refreshLoop;
    private DateTimeOffset _lastRefreshUtc = DateTimeOffset.MinValue;
    private bool _disposed;

    public IssuerKeyRing(
        HttpClient http,
        Uri endpoint,
        bool allowInsecure,
        TimeSpan refreshInterval,
        ILogger<IssuerKeyRing> logger)
    {
        _http = http;
        _endpoint = endpoint;
        _refreshInterval = refreshInterval <= TimeSpan.Zero ? TimeSpan.FromSeconds(5) : refreshInterval;
        _logger = logger;

        if (!allowInsecure && !endpoint.IsLoopback && !string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Issuer key directory must use HTTPS unless ALLOW_INSECURE_KEY_DIRECTORY=true is set for a local demo.");
        }

        if (allowInsecure && !string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            _logger.LogWarning(
                "ALLOW_INSECURE_KEY_DIRECTORY=true. This is acceptable for this Docker Compose demo only. " +
                "Production key-directory transport must be authenticated.");
        }
    }

    public int PublishedKeyCount => _cache.Count;

    public DateTimeOffset LastRefreshUtc => _lastRefreshUtc;

    public MLDsa? Resolve(string? kid)
    {
        if (string.IsNullOrWhiteSpace(kid))
        {
            return null;
        }

        return _cache.TryGetValue(kid, out var resolved) ? resolved : null;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await RefreshNowAsync(cancellationToken).ConfigureAwait(false);

        _refreshCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _refreshLoop = Task.Run(() => RefreshLoopAsync(_refreshCts.Token), CancellationToken.None);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_refreshCts is null)
        {
            return;
        }

        await _refreshCts.CancelAsync().ConfigureAwait(false);

        if (_refreshLoop is not null)
        {
            await Task.WhenAny(_refreshLoop, Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)).ConfigureAwait(false);
        }
    }

    public async Task RefreshNowAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = await _http.GetFromJsonAsync(
                _endpoint,
                IssuerKeyDirectoryJsonContext.Default.IssuerKeyDirectory,
                cancellationToken).ConfigureAwait(false);

            if (directory?.Keys is null)
            {
                _logger.LogWarning("Issuer key directory at {Endpoint} returned no keys.", _endpoint);
                _lastRefreshUtc = DateTimeOffset.UtcNow;
                return;
            }

            var published = new HashSet<string>(StringComparer.Ordinal);

            foreach (var entry in directory.Keys)
            {
                if (string.IsNullOrWhiteSpace(entry.Kid))
                {
                    continue;
                }

                published.Add(entry.Kid);

                if (!string.Equals(entry.Alg, PqJwtAlgorithms.MLDsa65, StringComparison.Ordinal))
                {
                    _logger.LogWarning("Ignoring issuer key kid={Kid} with unsupported alg={Alg}", entry.Kid, entry.Alg);
                    continue;
                }

                // Skip reimport when the published base64 matches what we
                // already imported for this kid. Avoids churning a fresh
                // native MLDsa handle through the quarantine on every ~5s
                // poll just because the background loop ran.
                if (_cachedKeyBase64.TryGetValue(entry.Kid, out var previousBase64) &&
                    string.Equals(previousBase64, entry.Key, StringComparison.Ordinal))
                {
                    continue;
                }

                try
                {
                    var bytes = Convert.FromBase64String(entry.Key);
                    var key = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, bytes);

                    // Capture any pre-existing key for deferred disposal — the
                    // AddOrUpdate factory runs under ConcurrentDictionary's per-bucket
                    // lock but Resolve() can have already read the OLD reference
                    // outside that lock, so disposing inline would race a native
                    // VerifyData call.
                    MLDsa? evicted = null;
                    _cache.AddOrUpdate(entry.Kid, key, (_, old) =>
                    {
                        evicted = old;
                        return key;
                    });
                    if (evicted is not null)
                    {
                        _quarantine.Enqueue((DateTimeOffset.UtcNow, evicted, entry.Kid));
                    }
                    _cachedKeyBase64[entry.Kid] = entry.Key;
                }
                catch (Exception ex) when (ex is FormatException or CryptographicException)
                {
                    _logger.LogWarning(ex, "Ignoring malformed issuer key kid={Kid}", entry.Kid);
                }
            }

            foreach (var cachedKid in _cache.Keys)
            {
                if (!published.Contains(cachedKid))
                {
                    if (_cache.TryRemove(cachedKid, out var evictedKey))
                    {
                        // Same race: a concurrent Resolve() may have already grabbed
                        // this reference. Quarantine, don't dispose inline.
                        _quarantine.Enqueue((DateTimeOffset.UtcNow, evictedKey, cachedKid));
                    }
                    _cachedKeyBase64.TryRemove(cachedKid, out _);
                    _logger.LogWarning("Evicted issuer key kid={Kid} because it is no longer published.", cachedKid);
                }
            }

            DrainExpiredQuarantine();

            _lastRefreshUtc = DateTimeOffset.UtcNow;
            _logger.LogInformation(
                "Issuer key directory refreshed from {Endpoint}; published keys={Count}",
                _endpoint,
                published.Count);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to refresh issuer key directory from {Endpoint}. Keeping existing cache.", _endpoint);
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private async Task RefreshLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_refreshInterval);

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                await RefreshNowAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
    }

    private void DrainExpiredQuarantine()
    {
        var now = DateTimeOffset.UtcNow;
        while (_quarantine.TryPeek(out var head) && (now - head.QuarantinedAt) >= QuarantineTtl)
        {
            if (_quarantine.TryDequeue(out var item))
            {
                try { item.Key.Dispose(); }
                catch (Exception ex) { _logger.LogWarning(ex, "Failed to dispose quarantined issuer key kid={Kid}", item.Kid); }
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _refreshCts?.Cancel();
        _refreshCts?.Dispose();
        _http.Dispose();

        foreach (var key in _cache.Values)
        {
            key.Dispose();
        }

        // Drain everything quarantined — the host is shutting down, no more
        // concurrent readers can appear.
        while (_quarantine.TryDequeue(out var item))
        {
            try { item.Key.Dispose(); } catch { /* swallow on shutdown */ }
        }

        _refreshLock.Dispose();
        _disposed = true;
    }
}

public sealed class IssuerKeyDirectory
{
    [JsonPropertyName("issuer")]
    public string Issuer { get; init; } = "";

    [JsonPropertyName("keys")]
    public IList<IssuerKeyEntry> Keys { get; init; } = [];
}

public sealed class IssuerKeyEntry
{
    [JsonPropertyName("kid")]
    public string Kid { get; init; } = "";

    [JsonPropertyName("status")]
    public string Status { get; init; } = "";

    [JsonPropertyName("alg")]
    public string Alg { get; init; } = "";

    [JsonPropertyName("key")]
    public string Key { get; init; } = "";
}

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(IssuerKeyDirectory))]
[JsonSerializable(typeof(IssuerKeyEntry))]
internal sealed partial class IssuerKeyDirectoryJsonContext : JsonSerializerContext;
