// PostQuantum.Jwt.WebApiDemo
// Minimal ASP.NET Core API demonstrating real integration of PostQuantum.Jwt
// via the PostQuantum.Jwt.AspNetCore companion (AddPqJwtBearer).
//
// Endpoints:
//   POST /token            : issue a signed ML-DSA-65 token (demo "login")
//   GET  /me               : protected; requires a valid PQ JWT
//   GET  /admin            : protected; requires the "admins" policy (role claim)
//   GET  /.well-known/pqjwt-keys : key directory (JWKS-equivalent)
//
// KEY LIFECYCLE (read this):
//   This demo generates a BRAND-NEW signing key every time the process starts.
//   That means: every restart invalidates every token issued before it. This is
//   deliberate for a zero-config demo, and it is exactly what a real service must
//   NOT do. A production issuer loads a persisted, securely-stored key (HSM, key
//   vault, sealed file) so tokens survive restarts and key rotation is explicit.
//   We log a loud warning at startup so this is impossible to miss.
//
// To God be the glory - 1 Corinthians 10:31.

using System.Diagnostics;
using System.Security.Cryptography;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;
using PostQuantum.Jwt.WebApiDemo;

const string Issuer = "https://demo.systemslibrarian.dev";
const string Audience = "https://api.demo.local";

var builder = WebApplication.CreateBuilder(args);

// -- Issuer signing key --------------------------------------------------------
// Two modes, chosen by the PQJWT_KEY_PATH environment variable:
//
//   (default, unset)  EPHEMERAL: a new key per process. Demonstrates the wrong
//                     thing on purpose, with a loud warning below. Restarting
//                     invalidates every token issued before it.
//
//   PQJWT_KEY_PATH=…  PERSISTENT: load (or first-time create) an encrypted
//                     PKCS#8 key file via FileBackedSigningKey, so issued tokens
//                     survive restarts. This is the production-SHAPED answer —
//                     see FileBackedSigningKey.cs for the real export/import
//                     lifecycle and why a file still isn't a vault.
//
// Either way the key is created ONCE and captured in closures, so the demo's
// trust relationship (this key signs; its public half verifies) lives in one place.
var keyPath = Environment.GetEnvironmentVariable("PQJWT_KEY_PATH");
FileBackedSigningKey? persisted = keyPath is null
    ? null
    : FileBackedSigningKey.LoadOrCreate(
        keyPath,
        Environment.GetEnvironmentVariable("PQJWT_KEY_PASSPHRASE")
            ?? "demo-passphrase-change-me");   // a real service pulls this from a secret store

string Kid = persisted?.KeyId ?? "demo-2026-01";
var signingKey = persisted?.SigningKey ?? MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
var publicKeyBytes = persisted?.PublicKeyBytes ?? signingKey.ExportMLDsaPublicKey();
var verificationKey = persisted?.VerificationKey
    ?? MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKeyBytes);

builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(options =>
    {
        options.ValidationParameters = new PqJwtValidationParameters
        {
            // Resolve by kid (enables rotation). The closure captures the public
            // key created above; an unknown kid resolves to null -> fail closed.
            SignatureKeyResolver = kid => kid == Kid ? verificationKey : null,
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            // Single-process replay defense. Swap for a Redis/SQL-backed
            // IPqJwtReplayCache when running more than one instance.
            ReplayCache = new InMemoryReplayCache(),
        };
    });

builder.Services.AddAuthorization(options =>
    options.AddPolicy("admins", p => p.RequireClaim("role", "admin")));

var app = builder.Build();

// -- Startup key-lifecycle log: honest about which mode is active. -----------
var startupLog = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
if (persisted is null)
{
    startupLog.LogWarning(
        "DEMO key lifecycle: EPHEMERAL. A NEW ML-DSA-65 signing key (kid={Kid}) was generated " +
        "at startup; all tokens issued by this process become invalid after a restart. Set " +
        "PQJWT_KEY_PATH to load/persist an encrypted key instead (see FileBackedSigningKey.cs).", Kid);
}
else
{
    startupLog.LogInformation(
        "Key lifecycle: PERSISTENT. ML-DSA-65 signing key (kid={Kid}) {Origin} encrypted PKCS#8 at the " +
        "configured path; tokens survive restarts. (A file still isn't a vault — see FileBackedSigningKey.cs.)",
        Kid, persisted.LoadedFromDisk ? "loaded from" : "generated and saved to");
}

// -- Lightweight request correlation so the logs feel like a real service. --
app.Use(async (ctx, next) =>
{
    var correlationId = ctx.Request.Headers.TryGetValue("X-Correlation-ID", out var incoming) && !string.IsNullOrEmpty(incoming)
        ? incoming.ToString()
        : Activity.Current?.Id ?? ctx.TraceIdentifier;
    ctx.Response.Headers["X-Correlation-ID"] = correlationId;

    using (app.Logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
    {
        var sw = Stopwatch.StartNew();
        await next();
        sw.Stop();
        app.Logger.LogInformation("{Method} {Path} -> {Status} in {Elapsed} ms",
            ctx.Request.Method, ctx.Request.Path, ctx.Response.StatusCode, sw.ElapsedMilliseconds);
    }
});

app.UseAuthentication();
app.UseAuthorization();

// -- Helpful-but-secure 401/403. We never reveal WHY auth failed (that would
// leak validator internals to an attacker); we return RFC 7807 problem details
// with a correlation id the operator can match against the logs. --------------
app.UseStatusCodePages(async ctx =>
{
    var r = ctx.HttpContext.Response;
    if (r.StatusCode is 401 or 403)
    {
        r.ContentType = "application/problem+json";
        var corr = r.Headers["X-Correlation-ID"].ToString();
        var detail = r.StatusCode == 401
            ? "No valid post-quantum bearer token was presented."
            : "The token is valid but lacks the required claim for this resource.";
        await r.WriteAsJsonAsync(new
        {
            type = "about:blank",
            title = r.StatusCode == 401 ? "Unauthorized" : "Forbidden",
            status = r.StatusCode,
            detail,
            correlationId = corr,
        });
    }
});

// -- Demo "login": issue a signed token -------------------------------------
// POST /token?sub=alice&role=admin
app.MapPost("/token", (string? sub, string? role, ILogger<Program> log) =>
{
    var b = new PqJwtBuilder()
        .WithIssuer(Issuer)
        .WithAudience(Audience)
        .WithSubject(sub ?? "demo-user")
        .WithLifetime(TimeSpan.FromMinutes(15))
        .WithKeyId(Kid)
        .WithJwtId(Guid.NewGuid().ToString("N"))
        .SignWith(signingKey);

    if (!string.IsNullOrEmpty(role))
        b = b.WithClaim("role", role);

    log.LogInformation("Issued token for sub={Sub} role={Role}", sub ?? "demo-user", role ?? "(none)");
    return Results.Ok(new { token = b.Build(), kid = Kid, token_type = "PqJwtBearer", expires_in = 900 });
});

// -- Protected: requires a valid PQ JWT -------------------------------------
app.MapGet("/me", (HttpContext ctx) => Results.Ok(new
{
    sub = ctx.User.FindFirst("sub")?.Value,
    role = ctx.User.FindFirst("role")?.Value,
    authenticated = ctx.User.Identity?.IsAuthenticated ?? false,
})).RequireAuthorization();

// -- Protected + role policy -------------------------------------------------
app.MapGet("/admin", () => Results.Ok(new { message = "Welcome, admin." }))
   .RequireAuthorization("admins");

// -- Key directory (JWKS-equivalent) ----------------------------------------
// Shape: { keys: [ { kid, alg, key(base64) } ] } - exactly what HttpPqJwtKeyRing
// fetches. A separate verifier service points its key ring at this URL and
// resolves verification keys by kid, with periodic refresh. That is how real
// multi-service rotation works: rotate the issuer's key + kid, publish both old
// and new here during the overlap window, and verifiers pick up the new one on
// their next refresh without redeploying.
app.MapGet("/.well-known/pqjwt-keys", () => Results.Ok(new
{
    keys = new[]
    {
        new { kid = Kid, alg = PqJwtAlgorithms.MLDsa65, key = Convert.ToBase64String(publicKeyBytes) }
    }
}));

app.MapGet("/", () => Results.Text(
    "PostQuantum.Jwt WebApiDemo. POST /token then GET /me with the bearer token. " +
    "Public keys at /.well-known/pqjwt-keys."));

app.Run();
