using System.Diagnostics;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
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

// DEMO-ONLY: when set, include the typed PqJwtFailureReason in the 401 problem-
// details response so the browser-driven landing page can show wire-truth instead
// of inferring reasons client-side. Production deployments must keep this OFF —
// leaking the typed reason gives an attacker a precise oracle of which validation
// gate they tripped (signature vs claims vs replay vs decryption), which is the
// whole point of returning generic 401s in production. The Container Apps
// deployment sets this to true; the docker-compose / local-dev path leaves it
// unset and behaves like production.
var exposeFailureReason = ParseBool(builder.Configuration["EXPOSE_FAILURE_REASON"], defaultValue: false);

// Demo recipient key. A real deployment should load this from a vault/HSM/sealed secret.
// Registered by factory so the DI container owns disposal.
builder.Services.AddSingleton(_ => XWingPrivateKey.Generate());

builder.Services.AddSingleton(sp =>
{
    var logger = sp.GetRequiredService<ILogger<IssuerKeyRing>>();
    // PooledConnectionLifetime forces the underlying socket pool to recycle
    // connections every 2 minutes, which is what makes a long-lived
    // HttpClient honor DNS TTLs in container environments (Azure Container
    // Apps, k8s, docker-compose). Without it, if the issuer container
    // recycles to a new IP, this Orders pod's existing connection points
    // at a dead endpoint forever and JWKS refresh silently fails. The
    // IssuerKeyRing owns this HttpClient (its Dispose cleans it up on
    // shutdown), so we don't need IHttpClientFactory's lifetime machinery
    // — we just need the handler's pool to rotate.
    var http = new HttpClient(new SocketsHttpHandler
    {
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    });
    return new IssuerKeyRing(
        http,
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

// Trust X-Forwarded-* from the Container Apps ingress so per-IP rate limiting
// and audit logs see the real client address instead of the LB.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// CORS for the browser-driven landing page (hosted on IssuerApi). Without
// this, the Issuer's landing page can't call Orders cross-origin from a
// browser. Allowed origins are env-configurable so the same image works
// behind any hostname the issuer is exposed at.
//
//   CORS_ALLOWED_ORIGINS = "https://demo.example.com,https://issuer.example.com"
//
// When the env is unset (local docker-compose), CORS is not enabled and the
// run-demo scripts (which run server-to-server, not browser-driven) keep
// working unchanged.
var corsOrigins = (builder.Configuration["CORS_ALLOWED_ORIGINS"] ?? "")
    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

if (corsOrigins.Length > 0)
{
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy => policy
            .WithOrigins(corsOrigins)
            .WithMethods("GET", "POST", "OPTIONS")
            .WithHeaders("Authorization", "Content-Type", "X-Correlation-ID")
            .WithExposedHeaders("X-Correlation-ID"));
    });
}

// Demo rate limit. OrdersApi sees more traffic per demo run (every verified
// request hits it), so the default is slightly higher than IssuerApi.
// Tighten for the live deployment via env (Container App sets
// RATE_LIMIT_PERMITS=20, RATE_LIMIT_WINDOW_SECONDS=60). Set
// RATE_LIMIT_PERMITS=0 to disable entirely (local testing).
var rateLimitPermits = int.TryParse(builder.Configuration["RATE_LIMIT_PERMITS"], out var parsedPermits)
    ? Math.Max(0, parsedPermits)
    : 60;
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
    "Issuer={Issuer}; Audience={Audience}; IssuerKeysUrl={IssuerKeysUrl}; KeyRefreshSeconds={RefreshSeconds}; RateLimit={Permits}/{Window}s",
    issuer,
    audience,
    issuerKeysUrl,
    refreshSeconds,
    rateLimitPermits,
    rateLimitWindowSeconds);

app.UseForwardedHeaders();

// UseStatusCodePages must be EARLY in the pipeline — before UseAuthentication —
// so it can intercept the 401 the auth challenge later sets. ASP.NET Core's
// status-code-pages middleware runs on the way back up the pipeline; if it's
// registered after auth, the 401 escapes past it and the response goes out
// with an empty body. (This is documented in
// https://learn.microsoft.com/aspnet/core/fundamentals/error-handling but easy
// to get wrong — symptom is content-length: 0 on every auth failure.)
app.UseStatusCodePages(async statusCodeContext =>
{
    var ctx = statusCodeContext.HttpContext;
    var response = ctx.Response;

    if (response.StatusCode is 401 or 403)
    {
        response.ContentType = "application/problem+json";
        var correlationId = response.Headers["X-Correlation-ID"].ToString();

        // DEMO-ONLY wire-truth: when EXPOSE_FAILURE_REASON is on, surface the
        // typed PqJwtFailureReason that PqJwtBearerHandler caught. We read it
        // from IAuthenticateResultFeature (set by the AuthenticationMiddleware
        // earlier in the pipeline) rather than calling AuthenticateAsync —
        // calling AuthenticateAsync from inside UseStatusCodePages can re-enter
        // the challenge pipeline mid-response. Reading the feature is a pure
        // lookup. Production deployments leave this off and return the generic
        // detail string only.
        string? failureReason = null;
        if (exposeFailureReason && response.StatusCode == 401)
        {
            // AspNetCore's AuthenticationMiddleware sets IAuthenticateResultFeature
            // only when authentication SUCCEEDS — on failure it never lands there.
            // The middleware below (registered between UseAuthentication and
            // UseAuthorization) captures the failure exception into HttpContext.Items
            // so we can surface the typed reason here.
            var authFailure = ctx.Items["PqJwtFailure"] as Exception;
            failureReason = authFailure switch
            {
                PqJwtValidationException pex => pex.Reason.ToString(),
                PqJwtException => "Unspecified",
                _ => null,
            };
        }

        await response.WriteAsJsonAsync(new
        {
            type = "about:blank",
            title = response.StatusCode == 401 ? "Unauthorized" : "Forbidden",
            status = response.StatusCode,
            detail = response.StatusCode == 401
                ? "No valid PostQuantum.Jwt bearer token was accepted."
                : "The token was valid but lacked the required authorization claim.",
            correlationId,
            failureReason, // null in production-shape; populated only when EXPOSE_FAILURE_REASON=true
        });
    }
});

// CORS must come before rate limiting and authentication so the browser's
// preflight OPTIONS request is answered with the right Access-Control-*
// headers even when the caller would otherwise be blocked.
if (corsOrigins.Length > 0)
{
    app.UseCors();
}

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

app.UseAuthentication();

// DEMO-ONLY: capture the typed PqJwtFailureReason from the bearer handler's
// AuthenticateResult.Failure so UseStatusCodePages (registered earlier in the
// pipeline) can surface it. AuthenticationMiddleware only writes
// IAuthenticateResultFeature on auth SUCCESS, so for failures we read the
// cached AuthenticateResult here and stash the exception in HttpContext.Items
// where the status-page handler reads it.
//
// IMPORTANT: this is a pure cached lookup, NOT a re-validation. The base
// AuthenticationHandler caches its HandleAuthenticateAsync result in a
// _authenticateTask field, and AuthenticateAsync(scheme) returns the same
// Task on every subsequent call within the same request. So the bearer
// handler's PqJwtValidator.Validate runs exactly once per request even
// though we touch AuthenticateAsync from two places (UseAuthentication +
// here). Verified against AspNetCore source
// (Microsoft.AspNetCore.Authentication.AuthenticationHandler<TOptions>).
//
// Gated by EXPOSE_FAILURE_REASON to keep production-shape clones from
// leaking the reason as a side effect of the same image.
if (exposeFailureReason)
{
    app.Use(async (ctx, next) =>
    {
        var result = await ctx.AuthenticateAsync(PqJwtBearerDefaults.AuthenticationScheme);
        if (result?.Failure is { } ex)
        {
            ctx.Items["PqJwtFailure"] = ex;
        }
        await next();
    });
}

app.UseAuthorization();

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

// DEMO-ONLY admin endpoint: forces an immediate IssuerKeyRing refresh and
// returns the cached kids. Used by the browser-driven landing page's step 8
// after a key-retirement so the demo can prove the verifier (NOT the issuer)
// has observed the retirement before sending T_retire. Without this, the
// landing page would poll the issuer-side JWKS as a proxy and might race the
// Orders background refresh, surfacing as a ReplayDetected/UnknownKeyId
// ambiguity in the demo narrative.
//
// Gated by EXPOSE_FAILURE_REASON so the same env that opens up the
// failure-reason field also opens this admin path. Production deployments
// must keep both off — an arbitrary caller forcing an unscheduled refresh
// can be a DoS vector against the issuer.
if (exposeFailureReason)
{
    app.MapPost("/admin/refresh-keys", async (IssuerKeyRing keyRing, CancellationToken ct) =>
    {
        await keyRing.RefreshNowAsync(ct);
        return Results.Ok(new
        {
            issuerKeysCached = keyRing.PublishedKeyCount,
            lastRefreshUtc = keyRing.LastRefreshUtc,
            note = "demo-only admin endpoint; gated by EXPOSE_FAILURE_REASON env",
        });
    });
}

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
