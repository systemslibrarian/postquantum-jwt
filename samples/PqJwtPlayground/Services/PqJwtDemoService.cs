// PqJwtPlayground — server-side crypto service.
//
// All post-quantum crypto runs on the SERVER (Blazor Server). The PQ primitives
// require a real .NET 10 runtime with OpenSSL 3.5+; they do not run in the
// browser. Demo keys live in this singleton for the life of the process and are
// never sent to the client.
//
// To God be the glory — 1 Corinthians 10:31.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.Jwt;
using PostQuantum.Jwt.Cryptography;
using Pq.Samples.Shared;

namespace PostQuantum.Jwt.Playground.Services;

/// <summary>Result of building a token, for display in the UI.</summary>
public sealed record BuildResult(
    string Token,
    int EncodedLength,
    int ApproxBytes,
    int Segments,
    bool Encrypted,
    double ElapsedMs,
    string DecodedHeaderJson,
    string DecodedPayloadJson);

/// <summary>Result of validating a token, for display in the UI.</summary>
public sealed record ValidationView(
    bool Valid,
    string Message,          // raw validator message (shown as technical detail)
    string What,             // plain-language headline when rejected
    string Why,              // plain-language explanation when rejected
    double ElapsedMs,
    bool WasEncrypted,
    string? Subject,
    string? Issuer,
    string? Audience,
    string? JwtId,
    string? ExpiresAt,
    string ClaimsJson);

/// <summary>One custom claim row from the UI. Value type is inferred safely.</summary>
public readonly record struct ClaimInput(string Name, string Value);

/// <summary>
/// Holds demo keys and wraps the library so Razor components stay thin.
/// Singleton: one key set per process. Regenerating replaces them.
/// </summary>
public sealed class PqJwtDemoService : IDisposable
{
    private readonly object _gate = new();
    private MLDsa _signingKey;
    private MLDsa _verificationKey;
    private XWingPrivateKey _recipientKey;

    public string SigningKid { get; private set; } = "playground-key-1";

    public PqJwtDemoService()
    {
        _signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        _verificationKey = MLDsa.ImportMLDsaPublicKey(
            MLDsaAlgorithm.MLDsa65, _signingKey.ExportMLDsaPublicKey());
        _recipientKey = XWingPrivateKey.Generate();
    }

    /// <summary>Base64 of the current ML-DSA-65 public verification key.</summary>
    public string VerificationPublicKeyBase64
    {
        get { lock (_gate) return Convert.ToBase64String(_verificationKey.ExportMLDsaPublicKey()); }
    }

    /// <summary>Base64 of the current X-Wing recipient public key (1216 bytes).</summary>
    public string RecipientPublicKeyBase64
    {
        get { lock (_gate) return Convert.ToBase64String(_recipientKey.PublicKey.Export()); }
    }

    /// <summary>Regenerate all demo keys. Previously issued tokens stop validating.</summary>
    public void RegenerateKeys()
    {
        lock (_gate)
        {
            _signingKey.Dispose();
            _verificationKey.Dispose();
            _recipientKey.Dispose();

            _signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
            _verificationKey = MLDsa.ImportMLDsaPublicKey(
                MLDsaAlgorithm.MLDsa65, _signingKey.ExportMLDsaPublicKey());
            _recipientKey = XWingPrivateKey.Generate();
            SigningKid = "playground-key-" + Random.Shared.Next(1000, 9999);
        }
    }

    /// <summary>
    /// Build a token from UI inputs. <paramref name="claims"/> are optional extra
    /// claims as name/value rows; each value is inferred to bool, long, double,
    /// or string (in that order) so the UI never has to hand us raw JSON.
    /// </summary>
    public BuildResult Build(
        string? subject,
        string? issuer,
        string? audience,
        int lifetimeMinutes,
        bool encrypt,
        bool includeJti,
        IReadOnlyList<ClaimInput>? claims)
    {
        lock (_gate)
        {
            var builder = new PqJwtBuilder()
                .WithLifetime(TimeSpan.FromMinutes(Math.Clamp(lifetimeMinutes, 1, 1440)))
                .WithKeyId(SigningKid);

            if (!string.IsNullOrWhiteSpace(subject)) builder = builder.WithSubject(subject);
            if (!string.IsNullOrWhiteSpace(issuer)) builder = builder.WithIssuer(issuer);
            if (!string.IsNullOrWhiteSpace(audience)) builder = builder.WithAudience(audience);
            if (includeJti) builder = builder.WithJwtId(Guid.NewGuid().ToString("N"));

            if (claims is not null)
            {
                foreach (var c in claims)
                {
                    if (string.IsNullOrWhiteSpace(c.Name)) continue;
                    builder = builder.WithClaim(c.Name, InferValue(c.Value));
                }
            }

            builder = builder.SignWith(_signingKey);
            if (encrypt) builder = builder.EncryptFor(_recipientKey.PublicKey);

            var sw = Stopwatch.StartNew();
            string token = builder.Build();
            sw.Stop();

            var segments = token.Split('.');
            var (header, payload) = DecodeForDisplay(segments, encrypt);

            return new BuildResult(
                Token: token,
                EncodedLength: token.Length,
                ApproxBytes: token.Length * 3 / 4,
                Segments: segments.Length,
                Encrypted: encrypt,
                ElapsedMs: sw.Elapsed.TotalMilliseconds,
                DecodedHeaderJson: header,
                DecodedPayloadJson: payload);
        }
    }

    // Infer a typed claim value from a UI string, most specific first.
    private static object InferValue(string raw)
    {
        if (bool.TryParse(raw, out var b)) return b;
        if (long.TryParse(raw, out var l)) return l;
        if (double.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture, out var d)) return d;
        return raw;
    }

    /// <summary>Validate a token against the current demo keys. Fail-closed: catches the throw.</summary>
    public ValidationView Validate(string token)
    {
        lock (_gate)
        {
            var validator = new PqJwtValidator(new PqJwtValidationParameters
            {
                SignatureVerificationKey = _verificationKey,
                DecryptionKey = _recipientKey,
                RequireReplayProtection = false,
            });

            var sw = Stopwatch.StartNew();
            try
            {
                var r = validator.Validate(token);
                sw.Stop();
                var claimsJson = JsonSerializer.Serialize(
                    r.Claims.ToDictionary(kv => kv.Key, kv => kv.Value),
                    new JsonSerializerOptions { WriteIndented = true });

                return new ValidationView(
                    Valid: true,
                    Message: "Token is valid.",
                    What: "Valid",
                    Why: "Signature verified, lifetime and claims passed every check.",
                    ElapsedMs: sw.Elapsed.TotalMilliseconds,
                    WasEncrypted: r.WasEncrypted,
                    Subject: r.Subject,
                    Issuer: r.Issuer,
                    Audience: r.GetString("aud"),
                    JwtId: r.JwtId,
                    ExpiresAt: r.ExpiresAt?.ToString("u"),
                    ClaimsJson: claimsJson);
            }
            catch (PqJwtValidationException ex)
            {
                sw.Stop();
                var (what, why) = RejectionExplainer.Explain(ex);
                return new ValidationView(
                    Valid: false,
                    Message: ex.Message,
                    What: what,
                    Why: why,
                    ElapsedMs: sw.Elapsed.TotalMilliseconds,
                    WasEncrypted: false,
                    Subject: null, Issuer: null, Audience: null, JwtId: null, ExpiresAt: null,
                    ClaimsJson: "{}");
            }
        }
    }

    // Decode header (and payload for signed tokens) purely for display.
    // Encrypted tokens have an opaque ciphertext payload, so we only show the header.
    private static (string Header, string Payload) DecodeForDisplay(string[] segments, bool encrypted)
    {
        string header = "{}";
        string payload = encrypted
            ? "\"(encrypted — payload is ciphertext until decrypted by the recipient)\""
            : "{}";
        try
        {
            if (segments.Length >= 1) header = Pretty(DecodeSegment(segments[0]));
            if (!encrypted && segments.Length >= 2) payload = Pretty(DecodeSegment(segments[1]));
        }
        catch { /* display-only; ignore decode hiccups */ }
        return (header, payload);
    }

    private static string DecodeSegment(string seg)
    {
        string s = seg.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(s));
    }

    private static string Pretty(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
        }
        catch { return json; }
    }

    public void Dispose()
    {
        _signingKey.Dispose();
        _verificationKey.Dispose();
        _recipientKey.Dispose();
    }
}
