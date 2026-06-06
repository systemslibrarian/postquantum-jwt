// PostQuantum.Jwt.VerifierDemo
//
// A SECOND service that verifies tokens minted by WebApiDemo (the issuer) WITHOUT
// sharing any signing key with it. It resolves verification keys at runtime by
// fetching the issuer's JWKS-equivalent directory (/.well-known/pqjwt-keys) over
// HTTP via HttpPqJwtKeyRing, keyed by the token's `kid`.
//
// This is the real multi-service rotation story made runnable: the issuer can
// rotate its signing key + kid and publish both old and new in its directory
// during the overlap window; this verifier picks up the new key on its next
// refresh - no redeploy, no shared secret, no manual key copying.
//
// Run it alongside the issuer with docker compose (see samples/docker-compose.yml),
// which sets ISSUER_KEYS_URL to the issuer's in-network address.
//
// To God be the glory - 1 Corinthians 10:31.

using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

const string Issuer = "https://demo.systemslibrarian.dev";
const string Audience = "https://api.demo.local";

var builder = WebApplication.CreateBuilder(args);

// Where to fetch the issuer's public keys. In compose this is the issuer
// service's internal URL; locally it defaults to the issuer's dev port.
var keysUrl = builder.Configuration["ISSUER_KEYS_URL"]
    ?? "http://localhost:5080/.well-known/pqjwt-keys";

// HttpPqJwtKeyRing is registered as BOTH a singleton AND a hosted service:
//   - The singleton holds the in-memory cache + the long-lived HttpClient.
//   - The hosted service runs StartAsync at app start — one preload, then a
//     PeriodicTimer-driven background refresh on the configured interval so
//     rotations are visible to /verify without a redeploy.
// Resolve(kid) is then a pure in-memory lookup on the auth request path,
// never blocking on HTTP. No signing key ever lives in this process — only
// the public verification keys it fetched from the issuer.
//
// The HttpClient's SocketsHttpHandler uses a 2-minute PooledConnectionLifetime
// so DNS TTLs are honored — important when the issuer container recycles to
// a new IP behind the same hostname.
builder.Services.AddSingleton(_ =>
    new HttpPqJwtKeyRing(
        new HttpClient(new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(2) }),
        new Uri(keysUrl),
        refreshInterval: TimeSpan.FromSeconds(30)));   // short, so rotation is visible in a demo
builder.Services.AddHostedService(sp => sp.GetRequiredService<HttpPqJwtKeyRing>());

builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(_ => { });

builder.Services
    .AddOptions<PqJwtBearerOptions>(PqJwtBearerDefaults.AuthenticationScheme)
    .Configure<HttpPqJwtKeyRing>((options, keyRing) =>
    {
        options.ValidationParameters = new PqJwtValidationParameters
        {
            // Every token's kid is resolved through the HTTP key ring's cache —
            // a pure in-memory lookup. The cache is kept current by the hosted
            // service's background refresh registered above.
            SignatureKeyResolver = kid => keyRing.Resolve(kid),
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            ReplayCache = new InMemoryReplayCache(),
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Text(
    $"PostQuantum.Jwt VerifierDemo. Verifies tokens via issuer keys at: {keysUrl}\n" +
    "Call GET /verify with an Authorization: Bearer <token> minted by the issuer."));

// Succeeds only if the token validates against a key fetched from the issuer.
app.MapGet("/verify", (HttpContext ctx) => Results.Ok(new
{
    verified = true,
    sub = ctx.User.FindFirst("sub")?.Value,
    role = ctx.User.FindFirst("role")?.Value,
    note = "Validated using a public key fetched from the issuer's /.well-known/pqjwt-keys.",
})).RequireAuthorization();

app.Run();
