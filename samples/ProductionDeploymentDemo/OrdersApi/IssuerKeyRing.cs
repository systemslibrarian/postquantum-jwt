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
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

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

                try
                {
                    var bytes = Convert.FromBase64String(entry.Key);
                    var key = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, bytes);

                    _cache.AddOrUpdate(entry.Kid, key, (_, old) =>
                    {
                        old.Dispose();
                        return key;
                    });
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
                    _cache.TryRemove(cachedKid, out _);
                    _logger.LogWarning("Evicted issuer key kid={Kid} because it is no longer published.", cachedKid);
                }
            }

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
