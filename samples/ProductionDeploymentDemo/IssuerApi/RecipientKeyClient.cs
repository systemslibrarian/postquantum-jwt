using System.Net.Http.Json;
using System.Text.Json.Serialization;
using PostQuantum.Jwt;
using PostQuantum.Jwt.Cryptography;

namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.IssuerApi;

/// <summary>
/// Fetches the Orders API public X-Wing recipient key so the issuer can produce
/// sign-then-encrypt tokens without ever seeing the Orders API private key.
/// </summary>
/// <remarks>
/// The client is registered as a singleton and caches the recipient public key for
/// a short interval. That makes recipient-key refresh deliberate instead of an
/// accidental per-request fetch or a forever cache. Real deployments should choose
/// a rotation policy, overlap window, and authenticated recipient-key directory.
/// </remarks>
public sealed class RecipientKeyClient
{
    private readonly HttpClient _http;
    private readonly Uri _endpoint;
    private readonly TimeSpan _refreshInterval;
    private readonly ILogger<RecipientKeyClient> _logger;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    private XWingPublicKey? _cached;
    private string? _cachedKid;
    private DateTimeOffset _lastFetched = DateTimeOffset.MinValue;

    public RecipientKeyClient(
        HttpClient http,
        Uri endpoint,
        TimeSpan refreshInterval,
        ILogger<RecipientKeyClient> logger)
    {
        _http = http;
        _endpoint = endpoint;
        _refreshInterval = refreshInterval <= TimeSpan.Zero ? TimeSpan.FromSeconds(30) : refreshInterval;
        _logger = logger;
    }

    public async Task<XWingPublicKey> GetRecipientPublicKeyAsync(CancellationToken cancellationToken)
    {
        if (_cached is not null && DateTimeOffset.UtcNow - _lastFetched < _refreshInterval)
        {
            return _cached;
        }

        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_cached is not null && DateTimeOffset.UtcNow - _lastFetched < _refreshInterval)
            {
                return _cached;
            }

            var document = await _http.GetFromJsonAsync(
                _endpoint,
                RecipientKeyJsonContext.Default.RecipientKeyDocument,
                cancellationToken).ConfigureAwait(false);

            if (document is null)
            {
                throw new InvalidOperationException("Recipient key endpoint returned an empty document.");
            }

            if (!string.Equals(document.Alg, PqJwtAlgorithms.XWing, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Recipient key endpoint returned alg '{document.Alg}', expected '{PqJwtAlgorithms.XWing}'.");
            }

            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(document.Key);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("Recipient key endpoint returned malformed base64.", ex);
            }

            _cached = XWingPublicKey.Import(bytes);
            _cachedKid = document.Kid;
            _lastFetched = DateTimeOffset.UtcNow;

            _logger.LogInformation(
                "Fetched Orders API X-Wing recipient public key kid={Kid}; cacheSeconds={Seconds}",
                _cachedKid,
                (int)_refreshInterval.TotalSeconds);

            return _cached;
        }
        finally
        {
            _refreshLock.Release();
        }
    }
}

public sealed class RecipientKeyDocument
{
    [JsonPropertyName("kid")]
    public string Kid { get; init; } = "";

    [JsonPropertyName("alg")]
    public string Alg { get; init; } = "";

    [JsonPropertyName("key")]
    public string Key { get; init; } = "";
}

[JsonSourceGenerationOptions(WriteIndented = false)]
[JsonSerializable(typeof(RecipientKeyDocument))]
internal sealed partial class RecipientKeyJsonContext : JsonSerializerContext;
