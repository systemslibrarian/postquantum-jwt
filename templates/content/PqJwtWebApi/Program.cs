// PostQuantum.Jwt — minimal ASP.NET Core API
//
//   POST /token?sub=alice&role=admin   issue a signed ML-DSA-65 token (demo "login")
//   GET  /me                           protected; requires a valid PQ JWT
//   GET  /admin                        protected; requires the "admins" policy
//   GET  /.well-known/pqjwt-keys       public key directory (JWKS-equivalent)
//
// Run, then:  curl -s -X POST "http://localhost:5000/token?sub=alice&role=admin"
//             curl -s http://localhost:5000/me -H "Authorization: Bearer <token>"
//
// NOTE: the native ML-DSA / ML-KEM primitives require OpenSSL 3.5+ at runtime.

using System.Security.Cryptography;
using PostQuantum.AspNetCore;
using PostQuantum.Jwt;

const string Issuer = "https://issuer.example";
const string Audience = "https://api.example";
const string Kid = "key-2026-01";

var builder = WebApplication.CreateBuilder(args);

// DEMO key lifecycle: a NEW ML-DSA-65 signing key is generated per process, so
// every restart invalidates previously issued tokens. A real issuer loads a
// persisted, securely-stored key (HSM, key vault, sealed file) instead.
var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
var publicKeyBytes = signingKey.ExportMLDsaPublicKey();
var verificationKey = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKeyBytes);

builder.Services
    .AddAuthentication(PostQuantumJwtBearerDefaults.AuthenticationScheme)
    .AddPostQuantumJwtBearer(options =>
    {
        options.ValidationParameters = new PqJwtValidationParameters
        {
            // Resolve by kid so key rotation is possible; an unknown kid resolves
            // to null -> the validator fails closed.
            SignatureKeyResolver = kid => kid == Kid ? verificationKey : null,
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            // Single-process replay defense. Swap for a Redis/SQL-backed
            // IPqJwtReplayCache when you run more than one instance.
            ReplayCache = new InMemoryReplayCache(),
        };
    });

builder.Services.AddAuthorization(options =>
    options.AddPolicy("admins", p => p.RequireClaim("role", "admin")));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Demo "login": issue a signed token.
app.MapPost("/token", (string? sub, string? role) =>
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

    return Results.Ok(new
    {
        token = b.Build(),
        token_type = PostQuantumJwtBearerDefaults.AuthenticationScheme,
        expires_in = 900,
    });
});

// Protected: requires a valid PQ JWT.
app.MapGet("/me", (HttpContext ctx) => Results.Ok(new
{
    sub = ctx.User.FindFirst("sub")?.Value,
    role = ctx.User.FindFirst("role")?.Value,
})).RequireAuthorization();

// Protected + role policy.
app.MapGet("/admin", () => Results.Ok(new { message = "Welcome, admin." }))
   .RequireAuthorization("admins");

// Key directory (JWKS-equivalent): a separate verifier service can resolve
// verification keys by kid from here and refresh periodically — that is how
// cross-service key rotation works.
app.MapGet("/.well-known/pqjwt-keys", () => Results.Ok(new
{
    keys = new[]
    {
        new { kid = Kid, alg = PqJwtAlgorithms.MLDsa65, key = Convert.ToBase64String(publicKeyBytes) }
    }
}));

app.MapGet("/", () => Results.Text(
    "PostQuantum.Jwt web API. POST /token then GET /me with the bearer token. " +
    "Public keys at /.well-known/pqjwt-keys."));

app.Run();
