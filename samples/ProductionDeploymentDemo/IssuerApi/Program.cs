using System.Diagnostics;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using PostQuantum.Jwt;
using PostQuantum.Jwt.Samples.ProductionDeploymentDemo.IssuerApi;

const string DefaultIssuer = "https://issuer.production-demo.local";
const string DefaultAudience = "https://orders.production-demo.local";
const string WrongAudience = "https://wrong-audience.production-demo.local";

var builder = WebApplication.CreateBuilder(args);

var issuer = builder.Configuration["PQJWT_ISSUER"] ?? DefaultIssuer;
var audience = builder.Configuration["PQJWT_AUDIENCE"] ?? DefaultAudience;
var encryptedByDefault = ParseBool(builder.Configuration["PQJWT_ENCRYPTED_TOKENS"], defaultValue: true);
var recipientKeyUrl = builder.Configuration["ORDERS_RECIPIENT_KEY_URL"]
    ?? "http://localhost:5190/.well-known/pqjwt-recipient-key";
var recipientKeyRefreshSeconds = int.TryParse(builder.Configuration["PQJWT_RECIPIENT_KEY_REFRESH_SECONDS"], out var parsedRecipientRefreshSeconds)
    ? Math.Clamp(parsedRecipientRefreshSeconds, 1, 3600)
    : 30;

builder.Services.AddSingleton<SigningKeyRing>();
builder.Services.AddHttpClient(nameof(RecipientKeyClient));
builder.Services.AddSingleton(sp => new RecipientKeyClient(
    sp.GetRequiredService<IHttpClientFactory>().CreateClient(nameof(RecipientKeyClient)),
    new Uri(recipientKeyUrl),
    TimeSpan.FromSeconds(recipientKeyRefreshSeconds),
    sp.GetRequiredService<ILogger<RecipientKeyClient>>()));

// Trust X-Forwarded-* from the Container Apps ingress so per-IP rate limiting
// sees the real client address instead of the ingress LB. KnownNetworks /
// KnownProxies are cleared because Container Apps' edge is not a fixed CIDR.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// Demo rate limit. Defaults are generous enough for the run-demo script's
// ~14 calls; tighten for the live deployment via env (the Container App sets
// RATE_LIMIT_PERMITS=10, RATE_LIMIT_WINDOW_SECONDS=60). Set
// RATE_LIMIT_PERMITS=0 to disable entirely (local testing).
var rateLimitPermits = int.TryParse(builder.Configuration["RATE_LIMIT_PERMITS"], out var parsedPermits)
    ? Math.Max(0, parsedPermits)
    : 30;
var rateLimitWindowSeconds = int.TryParse(builder.Configuration["RATE_LIMIT_WINDOW_SECONDS"], out var parsedWindow)
    ? Math.Clamp(parsedWindow, 1, 3600)
    : 60;

if (rateLimitPermits > 0)
{
    builder.Services.AddRateLimiter(options =>
    {
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
            RateLimitPartition.GetFixedWindowLimiter(
                partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                factory: _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = rateLimitPermits,
                    Window = TimeSpan.FromSeconds(rateLimitWindowSeconds),
                    QueueLimit = 0,
                }));
    });
}

var app = builder.Build();

app.Logger.LogWarning(
    "ProductionDeploymentDemo IssuerApi uses an IN-MEMORY signing key ring for demonstration. " +
    "Production issuers should use a vault, HSM, sealed secret, or another controlled key-management system.");
app.Logger.LogInformation(
    "Issuer={Issuer}; Audience={Audience}; EncryptedByDefault={Encrypted}; RecipientKeyUrl={RecipientKeyUrl}; RecipientKeyRefreshSeconds={RefreshSeconds}; RateLimit={Permits}/{Window}s",
    issuer,
    audience,
    encryptedByDefault,
    recipientKeyUrl,
    recipientKeyRefreshSeconds,
    rateLimitPermits,
    rateLimitWindowSeconds);

app.UseForwardedHeaders();

if (rateLimitPermits > 0)
{
    app.UseRateLimiter();
}

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

app.MapGet("/health", () => Results.Ok(new
{
    service = "issuer-api",
    status = "ok",
    encryptedByDefault,
    issuer,
    audience,
}));

app.MapGet("/", () => Results.Content(LandingPage.Html, "text/html; charset=utf-8"));

app.MapPost("/token", async (
    DemoTokenRequest? request,
    SigningKeyRing keyRing,
    RecipientKeyClient recipientKeyClient,
    ILogger<Program> log,
    CancellationToken cancellationToken) =>
{
    var response = await IssueTokenAsync(
        request,
        audienceOverride: null,
        expired: false,
        keyRing,
        recipientKeyClient,
        log,
        cancellationToken);

    return Results.Ok(response);
});

app.MapPost("/token/wrong-audience", async (
    DemoTokenRequest? request,
    SigningKeyRing keyRing,
    RecipientKeyClient recipientKeyClient,
    ILogger<Program> log,
    CancellationToken cancellationToken) =>
{
    var response = await IssueTokenAsync(
        request,
        audienceOverride: WrongAudience,
        expired: false,
        keyRing,
        recipientKeyClient,
        log,
        cancellationToken);

    return Results.Ok(response);
});

app.MapPost("/token/expired", async (
    DemoTokenRequest? request,
    SigningKeyRing keyRing,
    RecipientKeyClient recipientKeyClient,
    ILogger<Program> log,
    CancellationToken cancellationToken) =>
{
    var response = await IssueTokenAsync(
        request,
        audienceOverride: null,
        expired: true,
        keyRing,
        recipientKeyClient,
        log,
        cancellationToken);

    return Results.Ok(response);
});

app.MapPost("/keys/rotate", (SigningKeyRing keyRing, ILogger<Program> log) =>
{
    var result = keyRing.Rotate();
    log.LogWarning(
        "Signing key rotated. New active kid={ActiveKid}; previous kid={PreviousKid}; published keys={Count}",
        result.ActiveKid,
        result.PreviousKid,
        result.PublishedKeyCount);

    return Results.Ok(result);
});

app.MapPost("/keys/retire-previous", (SigningKeyRing keyRing, ILogger<Program> log) =>
{
    var result = keyRing.RetirePrevious();
    log.LogWarning(
        "Previous signing key retired. Retired kid={RetiredKid}; active kid={ActiveKid}; published keys={Count}",
        result.RetiredKid ?? "(none)",
        result.ActiveKid,
        result.PublishedKeyCount);

    return Results.Ok(result);
});

app.MapGet("/keys/status", (SigningKeyRing keyRing) =>
{
    var snapshot = keyRing.Snapshot();
    return Results.Ok(new
    {
        activeKid = snapshot.Active.Kid,
        previousKid = snapshot.Previous?.Kid,
        publishedKeyCount = keyRing.GetPublishedKeys().Count,
    });
});

app.MapGet("/.well-known/pqjwt-keys", (SigningKeyRing keyRing) => Results.Ok(new
{
    issuer,
    keys = keyRing.GetPublishedKeys(),
}));

app.Run();

async Task<object> IssueTokenAsync(
    DemoTokenRequest? request,
    string? audienceOverride,
    bool expired,
    SigningKeyRing keyRing,
    RecipientKeyClient recipientKeyClient,
    ILogger log,
    CancellationToken cancellationToken)
{
    var active = keyRing.Active;
    var tokenAudience = audienceOverride ?? audience;
    var subject = string.IsNullOrWhiteSpace(request?.Subject) ? "demo-user" : request.Subject!;
    var role = string.IsNullOrWhiteSpace(request?.Role) ? "reader" : request.Role!;
    var scope = string.IsNullOrWhiteSpace(request?.Scope) ? "orders.read" : request.Scope!;
    var encrypted = request?.Encrypted ?? encryptedByDefault;

    var tokenBuilder = new PqJwtBuilder()
        .WithIssuer(issuer)
        .WithAudience(tokenAudience)
        .WithSubject(subject)
        .WithJwtId(Guid.NewGuid().ToString("N"))
        .WithKeyId(active.Kid)
        .WithClaim("role", role)
        .WithClaim("scope", scope)
        .SignWith(active.Key);

    var lifetimeSeconds = Math.Clamp(request?.LifetimeSeconds ?? 300, 30, 3600);
    if (expired)
    {
        tokenBuilder = tokenBuilder.WithExpiration(DateTimeOffset.UtcNow.AddMinutes(-10));
    }
    else
    {
        tokenBuilder = tokenBuilder.WithLifetime(TimeSpan.FromSeconds(lifetimeSeconds));
    }

    if (encrypted)
    {
        var recipient = await recipientKeyClient.GetRecipientPublicKeyAsync(cancellationToken).ConfigureAwait(false);
        tokenBuilder = tokenBuilder.EncryptFor(recipient);
    }

    var token = tokenBuilder.Build();
    var parts = token.Count(static c => c == '.') + 1;

    log.LogInformation(
        "Issued {Mode} token kid={Kid} sub={Sub} aud={Aud} expired={Expired} parts={Parts}",
        encrypted ? "encrypted" : "signed-only",
        active.Kid,
        subject,
        tokenAudience,
        expired,
        parts);

    return new
    {
        access_token = token,
        token_type = "PqJwtBearer",
        expires_in = expired ? 0 : lifetimeSeconds,
        kid = active.Kid,
        encrypted,
        parts,
        issuer,
        audience = tokenAudience,
        subject,
        scope,
    };
}

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
