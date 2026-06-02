// PostQuantum.Jwt.RefreshTokenDemo
//
// The library's job is the ACCESS token: a short-lived, signed ML-DSA-65 JWT
// that proves "this is user X" and nothing more. But a bare access token can't
// be revoked and shouldn't be long-lived — so this demo shows the architecture
// that surrounds it: the access/refresh split with refresh-token ROTATION and
// REUSE DETECTION. This is the pattern that gives you working logout and
// revocation, which stateless JWTs alone cannot.
//
// Design (matches modern best practice):
//   • Access token  — ML-DSA-65 JWT, 15 min, carries ONLY `sub`. Sent on every
//                     API request. The library validates it. Never stored in
//                     localStorage in a real client — keep it in memory.
//   • Refresh token — opaque 64-byte random string (NOT a JWT). Long-lived.
//                     Only its SHA-256 HASH is stored server-side, so a store
//                     leak yields hashes, not usable tokens. Delivered in an
//                     HttpOnly, Secure, SameSite=Strict cookie scoped to
//                     /auth/refresh so it never rides along on normal requests.
//
// Rotation + reuse detection: every refresh issues a NEW refresh token and
// marks the old one used. If a used token is presented again, we assume theft
// and revoke the whole token "family". That is the mechanism behind real logout.
//
// DEMO STORAGE: an in-memory ConcurrentDictionary stands in for the database.
// A real service uses a durable, shared store (and the access-token signing key
// should be persisted — see WebApiDemo/FileBackedSigningKey.cs).
//
// To God be the glory - 1 Corinthians 10:31.

using System.Collections.Concurrent;
using System.Security.Cryptography;
using PostQuantum.Jwt;
using PostQuantum.Jwt.AspNetCore;

const string Issuer = "https://demo.systemslibrarian.dev";
const string Audience = "https://api.demo.local";
const string Kid = "refresh-demo-2026-01";
var AccessTokenTtl = TimeSpan.FromMinutes(15);
var RefreshTokenTtl = TimeSpan.FromDays(30);

var builder = WebApplication.CreateBuilder(args);

// Access-token signing key (ephemeral here; persist in production).
var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
var verificationKey = MLDsa.ImportMLDsaPublicKey(
    MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());

builder.Services
    .AddAuthentication(PqJwtBearerDefaults.AuthenticationScheme)
    .AddPqJwtBearer(options =>
    {
        options.ValidationParameters = new PqJwtValidationParameters
        {
            SignatureKeyResolver = kid => kid == Kid ? verificationKey : null,
            ValidIssuer = Issuer,
            ValidAudience = Audience,
        };
    });
builder.Services.AddAuthorization();

// Stand-in for the refresh-token table. Key = SHA-256(refresh token).
var store = new RefreshTokenStore();
builder.Services.AddSingleton(store);

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// Mints a short-lived access token carrying ONLY `sub`. Everything else
// (role, email, org) is looked up server-side when needed — so a leaked access
// token reveals nothing an attacker didn't already know to ask for.
string MintAccessToken(string userId) => new PqJwtBuilder()
    .WithIssuer(Issuer)
    .WithAudience(Audience)
    .WithSubject(userId)
    .WithKeyId(Kid)
    .WithJwtId(Guid.NewGuid().ToString("N"))
    .WithLifetime(AccessTokenTtl)
    .SignWith(signingKey)
    .Build();

// Issues a fresh opaque refresh token, stores only its hash, sets the cookie.
void IssueRefreshCookie(HttpResponse res, string userId, string family)
{
    var raw = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
    store.Add(Hash(raw), new RefreshRecord(userId, family,
        ExpiresAt: DateTimeOffset.UtcNow + RefreshTokenTtl));
    res.Cookies.Append("refresh_token", raw, new CookieOptions
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/auth/refresh",                 // never sent on normal requests
        MaxAge = RefreshTokenTtl,
    });
}

// -- Login: verify credentials (faked here), issue access + refresh ----------
app.MapPost("/auth/login", (string? user, HttpResponse res) =>
{
    // A real service checks a password hash here. The demo trusts the param.
    var userId = string.IsNullOrWhiteSpace(user) ? "demo-user" : user;
    IssueRefreshCookie(res, userId, family: Guid.NewGuid().ToString("N"));
    return Results.Ok(new { accessToken = MintAccessToken(userId), expiresInSeconds = (int)AccessTokenTtl.TotalSeconds });
});

// -- Refresh: rotate the refresh token, detect reuse, mint a new access token-
app.MapPost("/auth/refresh", (HttpRequest req, HttpResponse res) =>
{
    if (!req.Cookies.TryGetValue("refresh_token", out var presented) || string.IsNullOrEmpty(presented))
        return Results.Json(new { error = "Missing refresh token." }, statusCode: 401);

    var hash = Hash(presented);
    if (!store.TryGet(hash, out var record) || record.ExpiresAt < DateTimeOffset.UtcNow)
        return Results.Json(new { error = "Invalid or expired refresh token." }, statusCode: 401);

    // REUSE DETECTION: a token already marked used means either impossible
    // double-refresh or a stolen token. Assume theft; revoke the whole family.
    if (record.Used)
    {
        store.RevokeFamily(record.Family);
        return Results.Json(new { error = "Refresh token reuse detected — family revoked." }, statusCode: 401);
    }
    if (record.Revoked)
        return Results.Json(new { error = "Refresh token revoked." }, statusCode: 401);

    store.MarkUsed(hash);
    IssueRefreshCookie(res, record.UserId, record.Family);   // rotate within the same family
    return Results.Ok(new { accessToken = MintAccessToken(record.UserId), expiresInSeconds = (int)AccessTokenTtl.TotalSeconds });
});

// -- Logout: revoke server-side so the refresh token can't mint more ---------
app.MapPost("/auth/logout", (HttpRequest req, HttpResponse res) =>
{
    if (req.Cookies.TryGetValue("refresh_token", out var presented) && !string.IsNullOrEmpty(presented))
        store.Revoke(Hash(presented));
    res.Cookies.Delete("refresh_token", new CookieOptions { Path = "/auth/refresh" });
    // The current access token still works until it expires (<=15 min) — the
    // bounded blast radius is the whole point of short-lived access tokens.
    return Results.NoContent();
});

// -- A protected resource that consumes the access token ---------------------
app.MapGet("/me", (HttpContext ctx) => Results.Ok(new
{
    sub = ctx.User.FindFirst("sub")?.Value,
    note = "Access token carried only 'sub'; a real app looks up role/email server-side here.",
})).RequireAuthorization();

app.MapGet("/", () => Results.Text(
    "RefreshTokenDemo: POST /auth/login -> {accessToken} + refresh cookie. " +
    "POST /auth/refresh rotates. POST /auth/logout revokes. GET /me needs the access token. " +
    "See README.md for the full curl walkthrough incl. the reuse-detection demo."));

app.Run();

static string Hash(string raw) =>
    Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(raw)));

/// <summary>One stored refresh token (only its hash is the dictionary key).</summary>
internal sealed record RefreshRecord(string UserId, string Family, DateTimeOffset ExpiresAt)
{
    public bool Used { get; set; }
    public bool Revoked { get; set; }
}

/// <summary>In-memory stand-in for the refresh-token table. Thread-safe.</summary>
internal sealed class RefreshTokenStore
{
    private readonly ConcurrentDictionary<string, RefreshRecord> _byHash = new();

    public void Add(string hash, RefreshRecord record) => _byHash[hash] = record;
    public bool TryGet(string hash, out RefreshRecord record) => _byHash.TryGetValue(hash, out record!);
    public void MarkUsed(string hash) { if (_byHash.TryGetValue(hash, out var r)) r.Used = true; }
    public void Revoke(string hash) { if (_byHash.TryGetValue(hash, out var r)) r.Revoked = true; }

    public void RevokeFamily(string family)
    {
        foreach (var r in _byHash.Values)
            if (r.Family == family) r.Revoked = true;
    }
}
