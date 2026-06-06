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
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
    string DecodedPayloadJson,
    string CSharpSnippet);

/// <summary>One pre-canned tampering attack offered in the "Break it" panel.</summary>
public sealed record Attack(string Id, string Title, string Hint);

/// <summary>Outcome of running an <see cref="Attack"/>: what we changed, the
/// tampered token, and how the fail-closed validator responded.</summary>
public sealed record AttackResult(
    string Id,
    string Title,
    string Did,
    string TamperedToken,
    ValidationView Validation);

/// <summary>One custom claim in a shareable configuration.</summary>
public sealed record ShareClaim(string Name, string Value);

/// <summary>
/// A shareable playground configuration. Captures the <em>build form</em> only —
/// claims and options, NEVER key material. A restored link regenerates its own
/// session keys server-side, so a share link can't leak (or pin) private keys.
/// </summary>
public sealed record ShareState(
    string? Sub, string? Iss, string? Aud,
    int Minutes, bool Encrypt, bool Jti,
    List<ShareClaim> Claims);

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
                DecodedPayloadJson: payload,
                CSharpSnippet: BuildSnippet(encrypt, issuer, audience));
        }
    }

    // Ready-to-read C# that validates a token of exactly this shape with the real
    // library API. It mirrors what the playground does server-side, so a reader can
    // copy it into their own service. The verification key is referenced as a
    // server-held value — never pulled from the token — which is the whole point.
    private static string BuildSnippet(bool encrypt, string? issuer, string? audience)
    {
        var sb = new StringBuilder();
        sb.AppendLine("using PostQuantum.Jwt;");
        if (encrypt) sb.AppendLine("using PostQuantum.Jwt.Cryptography;");
        sb.AppendLine("using System.Security.Cryptography;");
        sb.AppendLine();
        sb.AppendLine("// The verification key is YOUR trusted public key, held server-side.");
        sb.AppendLine("// It is never read from the token's own header — that is how alg:none");
        sb.AppendLine("// and downgrade attacks are foreclosed. (This session's key is in panel 04.)");
        sb.AppendLine("byte[] publicKey = Convert.FromBase64String(verificationPublicKeyBase64);");
        sb.AppendLine("using var verificationKey = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, publicKey);");
        sb.AppendLine();
        sb.AppendLine("var validator = new PqJwtValidator(new PqJwtValidationParameters");
        sb.AppendLine("{");
        sb.AppendLine("    SignatureVerificationKey = verificationKey,");
        if (encrypt)
            sb.AppendLine("    DecryptionKey = recipientPrivateKey, // XWingPrivateKey held server-side");
        if (!string.IsNullOrWhiteSpace(issuer))
            sb.AppendLine($"    ValidIssuer = \"{EscapeForCSharp(issuer)}\",");
        if (!string.IsNullOrWhiteSpace(audience))
            sb.AppendLine($"    ValidAudience = \"{EscapeForCSharp(audience)}\",");
        sb.AppendLine("});");
        sb.AppendLine();
        sb.AppendLine("// Fail-closed: throws PqJwtValidationException if ANYTHING is wrong");
        sb.AppendLine("// (bad signature, expiry, wrong audience, malformed structure, …).");
        sb.AppendLine("PqJwtValidationResult result = validator.Validate(token);");
        sb.AppendLine("Console.WriteLine($\"sub = {result.Subject}, expires {result.ExpiresAt:u}\");");
        return sb.ToString();
    }

    private static string EscapeForCSharp(string s) =>
        s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);

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

    /// <summary>The tampering attacks offered in the "Break it" panel. Each one
    /// starts from a freshly-built valid token, mutates it, and is rejected — the
    /// four map to four <em>distinct</em> fail-closed reasons.</summary>
    public static readonly IReadOnlyList<Attack> Attacks = new[]
    {
        new Attack("alg", "Downgrade the algorithm",
            "Rewrite the header's alg to RS256 — the classic algorithm-substitution move."),
        new Attack("claim", "Tamper a claim",
            "Escalate role from user to superadmin in the payload, keep the old signature."),
        new Attack("sig", "Corrupt the signature",
            "Mangle the base64url signature segment so it no longer decodes."),
        new Attack("truncate", "Truncate the token",
            "Drop the signature segment entirely, leaving only header.payload."),
    };

    /// <summary>
    /// Run a Break-it attack: build a fresh, valid <em>signed</em> token, apply the
    /// named tamper, then push it through the same fail-closed validator. The point
    /// is to show the rejection — and the plain-language reason — for each attack.
    /// </summary>
    public AttackResult BreakIt(string attackId)
    {
        lock (_gate)
        {
            // A known-good signed token (never encrypted, so the payload is plain to
            // tamper with). Built with the live demo keys so the validator below uses
            // the matching verification key.
            var baseToken = new PqJwtBuilder()
                .WithSubject("user-123")
                .WithIssuer("https://issuer.example")
                .WithAudience("https://api.example")
                .WithClaim("role", "user")
                .WithLifetime(TimeSpan.FromMinutes(15))
                .WithKeyId(SigningKid)
                .SignWith(_signingKey)
                .Build();

            var parts = baseToken.Split('.');
            string tampered;
            string did;

            switch (attackId)
            {
                case "alg":
                    parts[0] = RewriteJsonField(parts[0], "alg", "RS256");
                    tampered = string.Join('.', parts);
                    did = "Rewrote the header's \"alg\" from ML-DSA-65 to RS256, then re-sent the same body.";
                    break;

                case "claim":
                    parts[1] = RewriteJsonField(parts[1], "role", "superadmin");
                    tampered = string.Join('.', parts);
                    did = "Edited the payload to escalate \"role\" from user to superadmin, leaving the original signature in place.";
                    break;

                case "sig":
                    parts[2] = CorruptSegment(parts[2]);
                    tampered = string.Join('.', parts);
                    did = "Corrupted bytes inside the base64url signature segment.";
                    break;

                case "truncate":
                    tampered = parts[0] + "." + parts[1];
                    did = "Removed the signature segment, leaving a 2-segment header.payload string.";
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(attackId), attackId, "Unknown attack.");
            }

            var title = Attacks.First(a => a.Id == attackId).Title;
            // Validate() also takes _gate; Monitor is re-entrant, so this is fine.
            return new AttackResult(attackId, title, did, tampered, Validate(tampered));
        }
    }

    // Decode a base64url JSON segment, set one field to a string value, re-encode.
    private static string RewriteJsonField(string segment, string field, string value)
    {
        var node = JsonNode.Parse(DecodeSegment(segment));
        var obj = node as JsonObject ?? new JsonObject();
        obj[field] = value;
        return Base64UrlEncode(Encoding.UTF8.GetBytes(obj.ToJsonString()));
    }

    // Replace two characters in the middle of a segment with a character outside the
    // base64url alphabet, so the validator's signature decode fails (SignatureMalformed)
    // — a distinct outcome from a claim tamper, which fails the signature *check*.
    private static string CorruptSegment(string segment)
    {
        if (segment.Length < 4) return segment + "!!";
        var chars = segment.ToCharArray();
        int mid = chars.Length / 2;
        chars[mid] = '!';
        chars[mid + 1] = '!';
        return new string(chars);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecodeBytes(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        // length % 4 == 1 is a structurally-invalid base64 length: there is no
        // padding to reach a multiple of four, and FromBase64String would throw
        // FormatException with an opaque "Invalid length" message. Throw our
        // own FormatException up front so the call sites' try/catch wrappers
        // (DecodeShare returns null; DecodeForDisplay swallows) get a clear
        // intent and copy-pasters of this helper aren't surprised.
        switch (s.Length % 4)
        {
            case 1: throw new FormatException("Invalid base64url length (mod 4 == 1).");
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    // Share links carry claims/options only — never keys. camelCase keeps the
    // encoded JSON (and therefore the URL) a little shorter.
    private static readonly JsonSerializerOptions ShareJson =
        new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>Encode a build configuration into a compact base64url string for a URL.</summary>
    public static string EncodeShare(ShareState state) =>
        Base64UrlEncode(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(state, ShareJson)));

    /// <summary>Decode a share code back into a configuration; returns null on any
    /// malformed/oversized input (it's untrusted, attacker-craftable URL data).</summary>
    public static ShareState? DecodeShare(string? code)
    {
        if (string.IsNullOrEmpty(code) || code.Length > 8192) return null;
        try
        {
            return JsonSerializer.Deserialize<ShareState>(
                Encoding.UTF8.GetString(Base64UrlDecodeBytes(code)), ShareJson);
        }
        catch
        {
            return null;
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
        // length % 4 == 1 is structurally invalid; throw early with a clear
        // message instead of letting FromBase64String throw an opaque one. The
        // caller (DecodeForDisplay) catches and swallows, so this is purely
        // a "fail honestly" hardening of the helper itself.
        switch (s.Length % 4)
        {
            case 1: throw new FormatException("Invalid base64url length (mod 4 == 1).");
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
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
