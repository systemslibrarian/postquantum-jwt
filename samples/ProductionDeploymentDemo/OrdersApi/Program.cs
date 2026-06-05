using System.Diagnostics;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;
using PostQuantum.Jwt.Cryptography;
using PostQuantum.Jwt.Samples.ProductionDeploymentDemo.OrdersApi;
using StackExchange.Redis;

const string DefaultIssuer = "https://issuer.production-demo.local";
const string DefaultAudience = "https://orders.production-demo.local";
const string RecipientKid = "orders-api-xwing-active";

var builder = WebApplication.CreateBuilder(args);

var issuer = builder.Configuration["PQJWT_ISSUER"] ?? DefaultIssuer;
var audience = builder.Configuration["PQJWT_AUDIENCE"] ?? DefaultAudience;
var issuerKeysUrl = builder.Configuration["ISSUER_KEYS_URL"]
    ?? "http://localhost:5180/.well-known/pqjwt-keys";
var allowInsecureKeyDirectory = ParseBool(builder.Configuration["ALLOW_INSECURE_KEY_DIRECTORY"], defaultValue: false);
var refreshSeconds = int.TryParse(builder.Configuration["PQJWT_KEY_REFRESH_SECONDS"], out var parsedRefreshSeconds)
    ? Math.Clamp(parsedRefreshSeconds, 1, 300)
    : 5;

// Demo recipient key. A real deployment should load this from a vault/HSM/sealed secret.
// Registered by factory so the DI container owns disposal.
builder.Services.AddSingleton(_ => XWingPrivateKey.Generate());

builder.Services.AddSingleton(sp =>
{
    var logger = sp.GetRequiredService<ILogger<IssuerKeyRing>>();
    return new IssuerKeyRing(
        new HttpClient(),
        new Uri(issuerKeysUrl),
        allowInsecureKeyDirectory,
        TimeSpan.FromSeconds(refreshSeconds),
        logger);
});

// Refresh issuer keys in the background. Resolve stays a pure in-memory lookup on
// the authentication request path; it never blocks on HTTP.
builder.Services.AddHostedService(sp => sp.GetRequiredService<IssuerKeyRing>());

builder.Services.AddSingleton<IPqJwtReplayCache>(sp =>
{
    var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("ReplayCache");
    var redisConnection = builder.Configuration["REDIS_CONNECTION"];

    if (!string.IsNullOrWhiteSpace(redisConnection))
    {
        logger.LogInformation("Using Redis replay cache at {RedisConnection}", redisConnection);
        var mux = ConnectionMultiplexer.Connect(redisConnection);
        return new RedisReplayCache(mux, ownsConnection: true);
    }

    logger.LogWarning(
        "REDIS_CONNECTION is not set. Falling back to InMemoryReplayCache. " +
        "This is single-process only and not sufficient for horizontally scaled deployments.");

    return new InMemoryReplayCache();
});

builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(_ => { });

// Configure the bearer options through DI instead of calling BuildServiceProvider
// during service registration. This is the production-shaped pattern: the handler
// receives the same singleton key ring, replay cache, and recipient key that the
// app actually runs with.
builder.Services
    .AddOptions<PqJwtBearerOptions>(PqJwtBearerDefaults.AuthenticationScheme)
    .Configure<IssuerKeyRing, IPqJwtReplayCache, XWingPrivateKey>((options, keyRing, replayCache, decryptionKey) =>
    {
        options.ValidationParameters = new PqJwtValidationParameters
        {
            SignatureKeyResolver = kid => keyRing.Resolve(kid),
            ValidIssuer = issuer,
            ValidAudience = audience,
            DecryptionKey = decryptionKey,
            ReplayCache = replayCache,
            RequireReplayProtection = true,
            ClockSkew = TimeSpan.FromSeconds(5),
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("orders.read", p => p.RequireClaim("scope", "orders.read"));
});

var app = builder.Build();

app.Logger.LogWarning(
    "ProductionDeploymentDemo OrdersApi uses an EPHEMERAL X-Wing recipient key for demonstration. " +
    "Production verifiers should load recipient private keys from a vault, HSM, or sealed secret.");
app.Logger.LogInformation(
    "Issuer={Issuer}; Audience={Audience}; IssuerKeysUrl={IssuerKeysUrl}; KeyRefreshSeconds={RefreshSeconds}",
    issuer,
    audience,
    issuerKeysUrl,
    refreshSeconds);

app.Use(async (ctx, next) =>
{
    var correlationId = ctx.Request.Headers.TryGetValue("X-Correlation-ID", out var incoming) && !string.IsNullOrWhiteSpace(incoming)
        ? incoming.ToString()
        : Activity.Current?.Id ?? ctx.TraceIdentifier;

    ctx.Response.Headers["X-Correlation-ID"] = correlationId;

    using (app.Logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
    {
        await next();
    }
});

app.UseAuthentication();
app.UseAuthorization();

app.UseStatusCodePages(async statusCodeContext =>
{
    var response = statusCodeContext.HttpContext.Response;

    if (response.StatusCode is 401 or 403)
    {
        response.ContentType = "application/problem+json";
        var correlationId = response.Headers["X-Correlation-ID"].ToString();

        await response.WriteAsJsonAsync(new
        {
            type = "about:blank",
            title = response.StatusCode == 401 ? "Unauthorized" : "Forbidden",
            status = response.StatusCode,
            detail = response.StatusCode == 401
                ? "No valid PostQuantum.Jwt bearer token was accepted."
                : "The token was valid but lacked the required authorization claim.",
            correlationId,
        });
    }
});

app.MapGet("/health", (IssuerKeyRing keyRing) =>
{
    var ready = keyRing.PublishedKeyCount > 0;
    var body = new
    {
        service = "orders-api",
        status = ready ? "ok" : "warming-up",
        issuer,
        audience,
        replay = string.IsNullOrWhiteSpace(app.Configuration["REDIS_CONNECTION"]) ? "memory" : "redis",
        recipientKid = RecipientKid,
        issuerKeysCached = keyRing.PublishedKeyCount,
        lastIssuerKeyRefreshUtc = keyRing.LastRefreshUtc,
    };

    return ready ? Results.Ok(body) : Results.Json(body, statusCode: StatusCodes.Status503ServiceUnavailable);
});

app.MapGet("/", () => Results.Text(
    "PostQuantum.Jwt ProductionDeploymentDemo OrdersApi. " +
    "GET /orders/123 with Authorization: Bearer <token>."));

app.MapGet("/.well-known/pqjwt-recipient-key", (XWingPrivateKey recipientKey) => Results.Ok(new
{
    kid = RecipientKid,
    alg = PqJwtAlgorithms.XWing,
    key = Convert.ToBase64String(recipientKey.PublicKey.Export()),
}));

app.MapGet("/orders/123", (HttpContext ctx) => Results.Ok(new
{
    orderId = "123",
    status = "validated",
    service = "orders-api",
    sub = ctx.User.FindFirst("sub")?.Value,
    role = ctx.User.FindFirst("role")?.Value,
    scope = ctx.User.FindFirst("scope")?.Value,
    note = "Token accepted after signature, issuer, audience, lifetime, kid, required-claim, decryption if needed, and replay validation.",
})).RequireAuthorization("orders.read");

app.Run();

static bool ParseBool(string? value, bool defaultValue)
{
    if (string.IsNullOrWhiteSpace(value))
    {
        return defaultValue;
    }

    return value.Equals("1", StringComparison.OrdinalIgnoreCase)
        || value.Equals("true", StringComparison.OrdinalIgnoreCase)
        || value.Equals("yes", StringComparison.OrdinalIgnoreCase);
}
