using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using PostQuantum.Jwt.AspNetCore;
using PostQuantum.Jwt.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// End-to-end tests for the ASP.NET Core companion package: AddPqJwtBearer,
/// the bearer handler, HttpPqJwtKeyRing, and how they plug into the standard
/// auth pipeline.
/// </summary>
public sealed class PqJwtAspNetCoreTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    [PqcFact]
    public async Task A_valid_bearer_token_authorizes_a_request()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("alice")
            .WithIssuer("https://issuer.example")
            .WithAudience("https://api.example")
            .WithClaim("role", "admin")
            .WithLifetime(TimeSpan.FromMinutes(10))
            .SignWith(signingKey)
            .Build();

        using var server = await CreateTestServer(signingKey, clock);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync(new Uri("/me", UriKind.Relative));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("alice", body, StringComparison.Ordinal);
        Assert.Contains("admin", body, StringComparison.Ordinal);
    }

    [PqcFact]
    public async Task A_missing_bearer_token_returns_401()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        using var server = await CreateTestServer(signingKey, clock);
        using var client = server.CreateClient();

        var response = await client.GetAsync(new Uri("/me", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PqcFact]
    public async Task A_tampered_bearer_token_returns_401()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("alice")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        // Flip a character in the signature segment.
        var parts = token.Split('.');
        parts[2] = parts[2][..^1] + (parts[2][^1] == 'A' ? 'B' : 'A');
        var tampered = string.Join('.', parts);

        using var server = await CreateTestServer(signingKey, clock);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tampered);

        var response = await client.GetAsync(new Uri("/me", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PqcFact]
    public async Task An_expired_bearer_token_returns_401()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var issueClock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(issueClock)
            .WithSubject("alice")
            .WithLifetime(TimeSpan.FromMinutes(1))
            .SignWith(signingKey)
            .Build();

        var laterClock = new FixedTimeProvider(Now.AddMinutes(10));
        using var server = await CreateTestServer(signingKey, laterClock);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync(new Uri("/me", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [PqcFact]
    public void Http_key_ring_resolves_known_kid_and_rejects_unknown_kid()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var publicKey = signingKey.ExportMLDsaPublicKey();
        var keyId = "rotated-2026";

        var directoryJson = $$"""
            { "keys": [ { "kid": "{{keyId}}", "alg": "ML-DSA-65", "key": "{{Convert.ToBase64String(publicKey)}}" } ] }
            """;

        using var fakeHandler = new StubHandler(directoryJson);
        using var httpClient = new HttpClient(fakeHandler);
        using var keyRing = new HttpPqJwtKeyRing(httpClient, new Uri("https://keys.example/.well-known/pq-keys"));

        var resolved = keyRing.Resolve(keyId);
        Assert.NotNull(resolved);
        Assert.Equal(MLDsaAlgorithm.MLDsa65, resolved!.Algorithm);

        Assert.Null(keyRing.Resolve("never-issued"));
    }

    [PqcFact]
    public async Task Http_key_ring_preload_caches_keys_for_kid_resolution()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var publicKey = signingKey.ExportMLDsaPublicKey();
        var keyId = "preload-test";

        var directoryJson = $$"""
            { "keys": [ { "kid": "{{keyId}}", "alg": "ML-DSA-65", "key": "{{Convert.ToBase64String(publicKey)}}" } ] }
            """;

        using var fakeHandler = new StubHandler(directoryJson);
        using var httpClient = new HttpClient(fakeHandler);
        using var keyRing = new HttpPqJwtKeyRing(httpClient, new Uri("https://keys.example/.well-known/pq-keys"));

        await keyRing.PreloadAsync(CancellationToken.None);

        Assert.Equal(1, fakeHandler.RequestCount);
        Assert.NotNull(keyRing.Resolve(keyId));
        // Subsequent resolves come from the in-memory cache — no extra HTTP calls.
        Assert.NotNull(keyRing.Resolve(keyId));
        Assert.Equal(1, fakeHandler.RequestCount);
    }

    [PqcFact]
    public async Task An_encrypted_token_with_no_decryption_key_returns_401_not_500()
    {
        // Regression: ValidateEncrypted throws the BASE PqJwtException (not
        // PqJwtValidationException) when no DecryptionKey is configured. The handler
        // must translate it to 401, not let it escape as an unhandled 500.
        using var signingKey = TestKeys.NewSigningKey();
        using var recipient = XWingPrivateKey.Generate();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithSubject("alice")
            .WithLifetime(TimeSpan.FromMinutes(10))
            .SignWith(signingKey)
            .EncryptFor(recipient.PublicKey)
            .Build();

        using var server = await CreateTestServer(signingKey, clock); // validator has no DecryptionKey
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync(new Uri("/me", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public void Http_key_ring_rejects_a_non_https_non_loopback_endpoint()
    {
        using var http = new HttpClient(new StubHandler("{}"));
        Assert.Throws<ArgumentException>(() =>
            new HttpPqJwtKeyRing(http, new Uri("http://keys.example/.well-known/pq-keys")));

        // Loopback over http is allowed for local development.
        using var loopback = new HttpPqJwtKeyRing(http, new Uri("http://localhost:5080/.well-known/pq-keys"));
        Assert.NotNull(loopback);
    }

    [PqcFact]
    public void Http_key_ring_evicts_a_kid_removed_from_the_directory()
    {
        // Regression: a revoked / rotated-out kid must stop resolving, not stay
        // trusted until process restart.
        using var signingKey = TestKeys.NewSigningKey();
        var pub = Convert.ToBase64String(signingKey.ExportMLDsaPublicKey());
        const string kid = "rotating-kid";
        var withKey = $$"""{ "keys": [ { "kid": "{{kid}}", "alg": "ML-DSA-65", "key": "{{pub}}" } ] }""";

        using var stub = new StubHandler(withKey);
        using var http = new HttpClient(stub);
        var clock = new MutableTimeProvider(Now);
        using var ring = new HttpPqJwtKeyRing(
            http, new Uri("https://keys.example/.well-known/pq-keys"), TimeSpan.FromMinutes(1), clock);

        Assert.NotNull(ring.Resolve(kid)); // first resolve fetches + caches

        // Issuer drops the key from the directory; advance past the refresh interval.
        stub.Response = """{ "keys": [] }""";
        clock.Now = Now.AddMinutes(2);

        Assert.Null(ring.Resolve(kid)); // due refresh evicts the removed kid
    }

    [PqcFact]
    public async Task A_misconfigured_validator_returns_401_not_500()
    {
        // Regression: the validator is constructed lazily inside the handler, and a
        // misconfiguration (RequireReplayProtection with no ReplayCache) throws an
        // ArgumentException there. It must fail closed (401), not escape as a 500.
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithSubject("alice").WithLifetime(TimeSpan.FromMinutes(10))
            .SignWith(signingKey).Build();

        using var verify = TestKeys.PublicKeyOf(signingKey);
        var badParams = new PqJwtValidationParameters
        {
            SignatureVerificationKey = verify,
            RequireReplayProtection = true, // no ReplayCache -> validator ctor throws
        };
        using var server = await CreateTestServer(signingKey, clock, badParams);
        using var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await client.GetAsync(new Uri("/me", UriKind.Relative));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<TestServer> CreateTestServer(
        MLDsa signingKey, TimeProvider clock, PqJwtValidationParameters? parameters = null)
    {
        using var pubKey = TestKeys.PublicKeyOf(signingKey);
        var publicKeyBytes = pubKey.ExportMLDsaPublicKey();

        var hostBuilder = new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddSingleton<TimeProvider>(clock);
                services
                    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
                    .AddPqJwtBearer(options =>
                    {
                        options.ValidationParameters = parameters ?? new PqJwtValidationParameters
                        {
                            SignatureVerificationKey = MLDsa.ImportMLDsaPublicKey(
                                MLDsaAlgorithm.MLDsa65, publicKeyBytes),
                        };
                        options.TimeProvider = clock;
                    });
                services.AddAuthorization();
                services.AddRouting();
            })
            .Configure(app =>
            {
                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/me", async ctx =>
                    {
                        if (!(ctx.User.Identity?.IsAuthenticated ?? false))
                        {
                            ctx.Response.StatusCode = 401;
                            return;
                        }

                        var sub = ctx.User.FindFirst("sub")?.Value ?? string.Empty;
                        var role = ctx.User.FindFirst("role")?.Value ?? string.Empty;
                        await ctx.Response.WriteAsync($"{{\"sub\":\"{sub}\",\"role\":\"{role}\"}}");
                    }).RequireAuthorization();
                });
            });

        var server = new TestServer(hostBuilder);
        await Task.CompletedTask;
        return server;
    }

    private sealed class StubHandler(string responseJson) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        /// <summary>The body returned on each call; mutable so a test can simulate the directory changing.</summary>
        public string Response { get; set; } = responseJson;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(Response, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        }
    }
}
