using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace PostQuantum.Jwt.AspNetCore;

/// <summary>
/// An <see cref="IPqJwtKeyRing"/> that maintains an in-memory cache of
/// ML-DSA-65 verification keys fetched from a trusted HTTPS endpoint. The
/// cache is refreshed on a configurable interval by a background loop;
/// <see cref="Resolve"/> is a pure in-memory lookup on the auth request path
/// and never performs synchronous-over-asynchronous HTTP.
/// </summary>
/// <remarks>
/// <para>
/// Register as both a singleton and a hosted service so the background
/// refresh runs:
/// </para>
/// <code>
/// services.AddSingleton(sp => new HttpPqJwtKeyRing(...));
/// services.AddHostedService(sp => sp.GetRequiredService&lt;HttpPqJwtKeyRing&gt;());
/// </code>
/// <para>
/// The expected wire format is a JSON object of the form
/// <c>{ "keys": [ { "kid": "...", "alg": "ML-DSA-65", "key": "&lt;base64 bytes&gt;" }, ... ] }</c>.
/// Entries with an <c>alg</c> other than <c>ML-DSA-65</c> are skipped — this is
/// the single-suite policy the library is built on.
/// </para>
/// </remarks>
public sealed class HttpPqJwtKeyRing : IPqJwtKeyRing, IHostedService, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly Uri _endpoint;
    private readonly TimeSpan _refreshInterval;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<HttpPqJwtKeyRing>? _logger;
    private readonly ConcurrentDictionary<string, MLDsa> _cache = new(StringComparer.Ordinal);

    // Parallel record of the base64 each kid was last imported from. Lets the
    // refresh loop skip re-importing a fresh native MLDsa handle when the
    // published key for a kid is unchanged — which is the common case on every
    // poll. Without this the cache would churn a handle through quarantine on
    // every interval even when nothing has actually rotated.
    private readonly ConcurrentDictionary<string, string> _cachedKeyBase64 = new(StringComparer.Ordinal);

    // Native MLDsa handles whose cache slot has been replaced or evicted. We do
    // NOT dispose them inline because a concurrent Resolve() may still hold the
    // reference returned from TryGetValue and be mid-VerifyData on its native
    // pointer; an inline old.Dispose() would race that and surface as an
    // ObjectDisposedException out of the ML-DSA verify. Disposal happens after
    // a TTL that is >> the longest realistic verify (~100 µs). Drained on
    // every refresh.
    private readonly ConcurrentQueue<(DateTimeOffset QuarantinedAt, MLDsa Key, string Kid)> _quarantine = new();
    private static readonly TimeSpan QuarantineTtl = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private DateTimeOffset _lastFetched = DateTimeOffset.MinValue;

    private CancellationTokenSource? _backgroundCts;
    private Task? _backgroundLoop;
    private bool _disposed;

    /// <summary>Creates an HTTP-backed key ring.</summary>
    /// <param name="httpClient">An <see cref="HttpClient"/> (typed-client friendly). The handler's connection pool must rotate periodically for DNS TTLs to be honored in container environments — configure <see cref="SocketsHttpHandler.PooledConnectionLifetime"/> or use <c>IHttpClientFactory</c>.</param>
    /// <param name="endpoint">The fully-qualified key-directory URL. Must use HTTPS (a loopback address is allowed for local development); a non-HTTPS, non-loopback endpoint is rejected at construction.</param>
    /// <param name="refreshInterval">How often the directory is re-fetched by the background loop. Defaults to 5 minutes.</param>
    /// <param name="timeProvider">Clock used for refresh timing.</param>
    /// <param name="logger">Optional logger.</param>
    public HttpPqJwtKeyRing(
        HttpClient httpClient,
        Uri endpoint,
        TimeSpan? refreshInterval = null,
        TimeProvider? timeProvider = null,
        ILogger<HttpPqJwtKeyRing>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(endpoint);

        // The key directory is the verifier's trust root: whoever controls the
        // response controls which ML-DSA keys are accepted. Fail fast on a
        // plaintext endpoint so a downgraded deployment can't enable on-path key
        // substitution. Loopback is allowed for local development and tests.
        if (!endpoint.IsLoopback && !string.Equals(endpoint.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"Key-directory endpoint must use HTTPS (got '{endpoint.Scheme}'). " +
                "It is the verifier's trust root; a plaintext fetch enables key substitution. " +
                "Use https://, or a loopback address for local development.",
                nameof(endpoint));
        }

        _httpClient = httpClient;
        _endpoint = endpoint;
        _refreshInterval = refreshInterval ?? TimeSpan.FromMinutes(5);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _logger = logger;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Pure in-memory lookup. Returns <c>null</c> if the kid isn't in the
    /// cache — the caller (typically <c>PqJwtBearerHandler</c>) should treat
    /// that as <c>UnknownKeyId</c>. The background refresh loop (started by
    /// <see cref="StartAsync"/>) is what keeps the cache current; if you
    /// register this type but never start it as a hosted service, the cache
    /// will stay empty until you call <see cref="PreloadAsync"/> manually.
    /// </remarks>
    public MLDsa? Resolve(string? keyId)
    {
        if (string.IsNullOrEmpty(keyId))
        {
            return null;
        }

        return _cache.TryGetValue(keyId, out var cached) ? cached : null;
    }

    /// <summary>
    /// Forces an immediate fetch of the key directory. Optional — used by
    /// tests, by <see cref="StartAsync"/>, and by hosts that want to fail at
    /// startup if the key endpoint is unreachable.
    /// </summary>
    public Task PreloadAsync(CancellationToken cancellationToken = default)
        => RefreshNowAsync(cancellationToken);

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        // One blocking fetch up-front so the cache is warm by the time the
        // first request arrives. Failure here is intentional — it surfaces
        // misconfiguration at startup rather than silently denying requests.
        await RefreshNowAsync(cancellationToken).ConfigureAwait(false);

        _backgroundCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _backgroundLoop = Task.Run(() => RefreshLoopAsync(_backgroundCts.Token), CancellationToken.None);
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_backgroundCts is null)
        {
            return;
        }

        await _backgroundCts.CancelAsync().ConfigureAwait(false);

        if (_backgroundLoop is not null)
        {
            await Task.WhenAny(_backgroundLoop, Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken)).ConfigureAwait(false);
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

    private async Task RefreshNowAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = await _httpClient
                .GetFromJsonAsync(_endpoint, PqJwtKeyRingJsonContext.Default.PqJwtKeyDirectory, cancellationToken)
                .ConfigureAwait(false);

            if (directory?.Keys is null)
            {
                _logger?.KeyRingEmpty(_endpoint);
                _lastFetched = _timeProvider.GetUtcNow();
                DrainExpiredQuarantine();
                return;
            }

            // Every kid the directory still lists — used below to evict kids the
            // issuer has rotated out or revoked. A kid that is listed but whose new
            // value is malformed stays in `published` (we keep the previously-good
            // key rather than drop it on a transient publish glitch).
            var published = new HashSet<string>(StringComparer.Ordinal);

            foreach (var entry in directory.Keys)
            {
                if (string.IsNullOrEmpty(entry.Kid))
                {
                    continue;
                }

                published.Add(entry.Kid);

                if (string.IsNullOrEmpty(entry.Key))
                {
                    continue;
                }

                if (!string.Equals(entry.Alg, PqJwtAlgorithms.MLDsa65, StringComparison.Ordinal))
                {
                    // Single-suite policy: anything other than ML-DSA-65 is ignored on purpose.
                    continue;
                }

                // Skip reimport when the published base64 matches what we
                // already imported for this kid. Avoids churning a fresh
                // native MLDsa handle through the quarantine on every poll
                // just because the background loop ran.
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
                    // AddOrUpdate factory runs under ConcurrentDictionary's
                    // per-bucket lock but Resolve() can have already read the
                    // OLD reference outside that lock, so disposing inline
                    // would race a native VerifyData call.
                    MLDsa? evicted = null;
                    _cache.AddOrUpdate(entry.Kid, key, (_, old) =>
                    {
                        evicted = old;
                        return key;
                    });
                    if (evicted is not null)
                    {
                        _quarantine.Enqueue((_timeProvider.GetUtcNow(), evicted, entry.Kid));
                    }
                    _cachedKeyBase64[entry.Kid] = entry.Key;
                }
                catch (Exception ex) when (ex is FormatException or CryptographicException)
                {
                    _logger?.KeyRingEntryMalformed(ex, entry.Kid);
                }
            }

            // Evict keys no longer published — this is what makes rotation and
            // revocation take effect before a process restart. Only happens after a
            // successful fetch (a failed fetch is caught below and keeps the cache
            // intact).
            foreach (var kid in _cache.Keys)
            {
                if (!published.Contains(kid))
                {
                    if (_cache.TryRemove(kid, out var evictedKey))
                    {
                        // Quarantine, don't dispose inline — a concurrent Resolve
                        // may have just handed this reference to an in-flight
                        // verify. The TTL covers the longest realistic verify
                        // call; deterministic disposal happens via the quarantine
                        // drain instead of the GC finalizer.
                        _quarantine.Enqueue((_timeProvider.GetUtcNow(), evictedKey, kid));
                    }
                    _cachedKeyBase64.TryRemove(kid, out _);
                }
            }

            DrainExpiredQuarantine();

            _lastFetched = _timeProvider.GetUtcNow();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.KeyRingFetchFailed(ex, _endpoint);
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private void DrainExpiredQuarantine()
    {
        var now = _timeProvider.GetUtcNow();
        while (_quarantine.TryPeek(out var head) && (now - head.QuarantinedAt) >= QuarantineTtl)
        {
            if (_quarantine.TryDequeue(out var item))
            {
                try { item.Key.Dispose(); }
                catch (Exception ex) { _logger?.KeyRingQuarantineDisposeFailed(ex, item.Kid); }
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _backgroundCts?.Cancel();
        _backgroundCts?.Dispose();

        foreach (var key in _cache.Values)
        {
            try { key.Dispose(); } catch { /* swallow on shutdown */ }
        }

        // Drain everything quarantined — no concurrent readers can appear after
        // the host has called Dispose.
        while (_quarantine.TryDequeue(out var item))
        {
            try { item.Key.Dispose(); } catch { /* swallow on shutdown */ }
        }

        _refreshLock.Dispose();
        _disposed = true;
    }
}

/// <summary>One entry in the HTTP-fetched key directory.</summary>
public sealed class PqJwtKeyEntry
{
    /// <summary>The key identifier referenced by a token's <c>kid</c> header.</summary>
    [JsonPropertyName("kid")]
    public string Kid { get; init; } = "";

    /// <summary>The algorithm identifier; must be <c>"ML-DSA-65"</c>.</summary>
    [JsonPropertyName("alg")]
    public string Alg { get; init; } = "";

    /// <summary>Base64-encoded raw ML-DSA-65 public key bytes.</summary>
    [JsonPropertyName("key")]
    public string Key { get; init; } = "";
}

/// <summary>Top-level shape of the HTTP key directory document.</summary>
public sealed class PqJwtKeyDirectory
{
    /// <summary>The published keys.</summary>
    [JsonPropertyName("keys")]
    public IList<PqJwtKeyEntry> Keys { get; init; } = [];
}

/// <summary>Source-generated JSON metadata for the key-ring types — keeps the package AOT-safe.</summary>
[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(PqJwtKeyDirectory))]
[JsonSerializable(typeof(PqJwtKeyEntry))]
internal sealed partial class PqJwtKeyRingJsonContext : JsonSerializerContext;
