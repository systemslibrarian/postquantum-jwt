// PostQuantum.Jwt.ConsoleDemo
// Educational console application demonstrating the PostQuantum.Jwt library.
//
// Shows: ML-DSA-65 signing, optional X-Wing (X25519 + ML-KEM-768) hybrid
// encryption, replay protection, kid resolution, token size/timing, and the
// library's fail-closed validation behavior (invalid tokens THROW; there is
// no "best-effort" result).
//
// This is a DEMO. Keys live only in memory; do not copy these key-handling
// patterns into production without real key management.
//
// To God be the glory — 1 Corinthians 10:31.

using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using PostQuantum.Jwt;
using PostQuantum.Jwt.Cryptography;
using Spectre.Console;
using Pq.Samples.Shared;

namespace PostQuantum.Jwt.ConsoleDemo;

internal static class Program
{
    // Session state. Held in memory only.
    private static MLDsa? _signingKey;          // private signing key (ML-DSA-65)
    private static MLDsa? _verificationKey;      // public verification key
    private static string _signingKid = "demo-signing-key-2026";
    private static XWingPrivateKey? _recipientKey;   // for the encrypt demo

    public static async Task Main()
    {
        AnsiConsole.Clear();
        ShowHeader();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        try
        {
            await RunMainLoopAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            AnsiConsole.MarkupLine("\n[yellow]Cancelled.[/]");
        }
        catch (Exception ex)
        {
            AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
        }
        finally
        {
            DisposeKeys();
            AnsiConsole.MarkupLine("\n[dim]To God be the glory — 1 Corinthians 10:31.[/]");
        }
    }

    private static void ShowHeader()
    {
        AnsiConsole.Write(new Rule("[bold blue]Post-Quantum JWT — Console Demo[/]").RuleStyle("blue"));
        AnsiConsole.MarkupLine("[dim]ML-DSA-65 signatures + optional X-Wing (X25519 + ML-KEM-768) encryption · .NET 10[/]");
        AnsiConsole.MarkupLine("[dim]PostQuantum.Jwt 1.0.0-preview.1 · preview software, not for production[/]\n");
    }

    private static async Task RunMainLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[bold]Choose an action:[/]")
                    .PageSize(14)
                    .AddChoices(
                        "1. Generate ML-DSA keypair",
                        "2. Create signed token (ML-DSA-65 only)",
                        "3. Create sign-then-encrypt token (X-Wing)",
                        "4. Validate a token",
                        "5. Replay protection demo",
                        "6. Key rotation (kid resolver) demo",
                        "7. Attack mode (wrong key / expired / tampered / replay)",
                        "8. View current session keys",
                        "9. Security notes & limitations",
                        "0. Exit"));

            if (choice.StartsWith('0')) break;

            AnsiConsole.Clear();
            ShowHeader();

            try
            {
                switch (choice[0])
                {
                    case '1': GenerateKeypair(); break;
                    case '2': CreateSignedToken(); break;
                    case '3': CreateEncryptedToken(); break;
                    case '4': await ValidateTokenInteractiveAsync(); break;
                    case '5': ReplayProtectionDemo(); break;
                    case '6': KeyRotationDemo(); break;
                    case '7': AttackMode(); break;
                    case '8': ShowCurrentKeys(); break;
                    case '9': ShowSecurityNotes(); break;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(ex.Message)}");
            }

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]Press any key to return to the menu...[/]");
            Console.ReadKey(true);
            AnsiConsole.Clear();
            ShowHeader();
        }
    }

    // ── 1. Key generation ────────────────────────────────────────────────
    private static void GenerateKeypair()
    {
        AnsiConsole.MarkupLine("[bold green]Generating ML-DSA-65 keypair...[/]");
        var sw = Stopwatch.StartNew();

        DisposeKeys();
        _signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        _verificationKey = MLDsa.ImportMLDsaPublicKey(
            MLDsaAlgorithm.MLDsa65, _signingKey.ExportMLDsaPublicKey());

        sw.Stop();
        AnsiConsole.MarkupLine($"[green]✓[/] Generated in [yellow]{sw.ElapsedMilliseconds} ms[/]\n");

        var pub = _verificationKey.ExportMLDsaPublicKey();
        var table = new Table().Border(TableBorder.Rounded)
            .AddColumn("Key").AddColumn("Algorithm").AddColumn("Public key (bytes)");
        table.AddRow("Signing (private, kept in memory)", "ML-DSA-65", "[dim]not exported[/]");
        table.AddRow("Verification (public, shareable)", "ML-DSA-65", pub.Length.ToString());
        AnsiConsole.Write(table);

        AnsiConsole.MarkupLine("\n[dim]Private key material is never printed. Only the public key is exportable here.[/]");
    }

    // ── 2. Signed token ──────────────────────────────────────────────────
    private static void CreateSignedToken()
    {
        if (!RequireKeys()) return;

        var subject = AnsiConsole.Ask("Subject:", "demo-user-42");
        var minutes = AnsiConsole.Ask("Lifetime (minutes):", 15);

        var sw = Stopwatch.StartNew();
        string token = new PqJwtBuilder()
            .WithIssuer("https://demo.systemslibrarian.dev")
            .WithSubject(subject)
            .WithAudience("https://api.demo.local")
            .WithLifetime(TimeSpan.FromMinutes(minutes))
            .WithKeyId(_signingKid)
            .WithJwtId(Guid.NewGuid().ToString("N"))
            .WithClaim("role", "reader")
            .SignWith(_signingKey!)
            .Build();
        sw.Stop();

        DisplayToken("Signed (ML-DSA-65)", token, sw.Elapsed, encrypted: false);
    }

    // ── 3. Sign + encrypt token ──────────────────────────────────────────
    private static void CreateEncryptedToken()
    {
        if (!RequireKeys()) return;

        _recipientKey ??= XWingPrivateKey.Generate();
        var recipientPublic = _recipientKey.PublicKey;   // XWingPublicKey

        var subject = AnsiConsole.Ask("Confidential subject:", "confidential-789");
        var minutes = AnsiConsole.Ask("Lifetime (minutes):", 5);

        var sw = Stopwatch.StartNew();
        string token = new PqJwtBuilder()
            .WithSubject(subject)
            .WithLifetime(TimeSpan.FromMinutes(minutes))
            .WithKeyId(_signingKid)
            .WithJwtId(Guid.NewGuid().ToString("N"))
            .SignWith(_signingKey!)
            .EncryptFor(recipientPublic)
            .Build();
        sw.Stop();

        DisplayToken("Sign-then-encrypt (ML-DSA-65 + X-Wing → A256GCM)", token, sw.Elapsed, encrypted: true);
        AnsiConsole.MarkupLine("\n[dim]The session recipient key is held in memory; validate with option 4 while this session lives.[/]");
    }

    private static void DisplayToken(string title, string token, TimeSpan elapsed, bool encrypted)
    {
        AnsiConsole.Write(new Rule($"[bold]{title}[/]").RuleStyle("green"));
        AnsiConsole.Write(new Panel(Markup.Escape(token))
            .Header("Compact token (copy this)").Border(BoxBorder.Rounded).Padding(1, 0));

        var info = new Table().Border(TableBorder.None).AddColumn("Property").AddColumn("Value");
        info.AddRow("Encoded length", $"{token.Length} chars (~{token.Length * 3 / 4} bytes)");
        info.AddRow("Segments", encrypted ? "5 (JWE-style)" : "3 (JWS-style)");
        info.AddRow("Creation time", $"{elapsed.TotalMilliseconds:F1} ms");
        info.AddRow("Encrypted", encrypted ? "[green]Yes (X-Wing + A256GCM)[/]" : "[yellow]No (signed only)[/]");
        AnsiConsole.Write(info);
    }

    // ── 4. Validate ──────────────────────────────────────────────────────
    private static Task ValidateTokenInteractiveAsync()
    {
        if (_verificationKey is null)
        {
            AnsiConsole.MarkupLine("[red]No verification key. Generate a keypair first (option 1).[/]");
            return Task.CompletedTask;
        }

        var token = AnsiConsole.Ask<string>("Paste token to validate:");

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verificationKey,
            DecryptionKey = _recipientKey,   // null is fine for signed-only tokens
            RequireReplayProtection = false,
        });

        var sw = Stopwatch.StartNew();
        try
        {
            // Fail-closed: this returns ONLY on success, otherwise it throws.
            var result = validator.Validate(token);
            sw.Stop();

            var t = new Table().Border(TableBorder.Rounded).Title("[bold green]✓ Valid[/]")
                .AddColumn("Claim").AddColumn("Value");
            t.AddRow("sub", result.Subject ?? "[dim]none[/]");
            t.AddRow("iss", result.Issuer ?? "[dim]none[/]");
            t.AddRow("aud", result.GetString("aud") ?? "[dim]none[/]");
            t.AddRow("jti", result.JwtId ?? "[dim]none[/]");
            t.AddRow("exp", result.ExpiresAt?.ToString("u") ?? "[dim]none[/]");
            t.AddRow("Encrypted", result.WasEncrypted ? "[green]Yes[/]" : "[yellow]No[/]");
            t.AddRow("Validation time", $"{sw.ElapsedMilliseconds} ms");
            AnsiConsole.Write(t);

            if (result.Claims.Count > 0)
            {
                AnsiConsole.MarkupLine("\n[bold]All claims:[/]");
                AnsiConsole.WriteLine(JsonSerializer.Serialize(
                    result.Claims.ToDictionary(kv => kv.Key, kv => kv.Value),
                    new JsonSerializerOptions { WriteIndented = true }));
            }
        }
        catch (PqJwtValidationException ex)
        {
            sw.Stop();
            var (what, why) = RejectionExplainer.Explain(ex);
            AnsiConsole.MarkupLine($"[red]✗ Rejected[/] after {sw.ElapsedMilliseconds} ms — [white]{Markup.Escape(what)}[/]");
            AnsiConsole.MarkupLine($"[dim]{Markup.Escape(why)}[/]");
            AnsiConsole.MarkupLine($"[dim]validator: {Markup.Escape(ex.Message)}[/]");
        }
        return Task.CompletedTask;
    }

    // ── 5. Replay protection ─────────────────────────────────────────────
    private static void ReplayProtectionDemo()
    {
        if (!RequireKeys()) return;

        var cache = new InMemoryReplayCache();
        string token = new PqJwtBuilder()
            .WithSubject("replay-test")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .WithJwtId(Guid.NewGuid().ToString("N"))
            .SignWith(_signingKey!)
            .Build();

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verificationKey,
            ReplayCache = cache,
            RequireReplayProtection = true,
        });

        try
        {
            validator.Validate(token);
            AnsiConsole.MarkupLine("[green]✓ First use accepted (jti registered).[/]");
        }
        catch (PqJwtValidationException ex)
        {
            AnsiConsole.MarkupLine($"[red]Unexpected first-use failure:[/] {Markup.Escape(ex.Message)}");
            return;
        }

        try
        {
            validator.Validate(token);
            AnsiConsole.MarkupLine("[red]✗ Second use accepted — replay was NOT detected![/]");
        }
        catch (PqJwtValidationException)
        {
            AnsiConsole.MarkupLine("[green]✓ Second use correctly rejected as a replay.[/]");
        }
    }

    // ── 6. Key rotation / kid resolver ───────────────────────────────────
    private static void KeyRotationDemo()
    {
        AnsiConsole.MarkupLine("[bold]Two signing keys, resolved by [yellow]kid[/] at validation time.[/]\n");

        using var keyA = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var keyB = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var pubA = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, keyA.ExportMLDsaPublicKey());
        using var pubB = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, keyB.ExportMLDsaPublicKey());

        var ring = new Dictionary<string, MLDsa> { ["key-A"] = pubA, ["key-B"] = pubB };

        string tokenB = new PqJwtBuilder()
            .WithSubject("rotated-user")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .WithKeyId("key-B")
            .SignWith(keyB)
            .Build();

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureKeyResolver = kid => kid is not null && ring.TryGetValue(kid, out var k) ? k : null,
        });

        try
        {
            var r = validator.Validate(tokenB);
            AnsiConsole.MarkupLine($"[green]✓ Token signed with key-B validated via resolver.[/] sub = {r.Subject}");
        }
        catch (PqJwtValidationException ex)
        {
            AnsiConsole.MarkupLine($"[red]✗ {Markup.Escape(ex.Message)}[/]");
        }

        AnsiConsole.MarkupLine("\n[dim]An unknown kid resolves to null → fail-closed rejection. Rotate by adding the new kid to the ring before issuing with it.[/]");
    }

    // ── 7. Attack mode ───────────────────────────────────────────────────
    // A guided walk through realistic forgery attempts. Each one is the kind of
    // thing an attacker who has captured a valid token would actually try; each
    // must fail closed, and we explain *why* in plain language so the mechanism
    // — not just the outcome — is visible.
    private static void AttackMode()
    {
        if (!RequireKeys()) return;
        AnsiConsole.Write(new Rule("[bold red]Attack mode[/]").RuleStyle("red"));
        AnsiConsole.MarkupLine("[dim]An attacker holds a captured, valid token. Watch each forgery attempt fail closed.[/]\n");

        var honestValidator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verificationKey,
        });

        // The legitimate token the attacker starts from: a low-privilege user.
        string captured = new PqJwtBuilder()
            .WithIssuer("https://demo.systemslibrarian.dev")
            .WithSubject("alice")
            .WithLifetime(TimeSpan.FromMinutes(15))
            .WithClaim("role", "reader")
            .SignWith(_signingKey!)
            .Build();

        // Sanity: the captured token is genuinely valid before we attack it.
        try
        {
            var ok = honestValidator.Validate(captured);
            AnsiConsole.MarkupLine($"[dim]Baseline: captured token is valid. sub={ok.Subject}, role={ok.GetString("role")}.[/]\n");
        }
        catch (PqJwtValidationException)
        {
            AnsiConsole.MarkupLine("[red]Baseline token failed to validate — environment problem, aborting attack demo.[/]");
            return;
        }

        // (1) Privilege escalation by editing a CLAIM and keeping the old signature.
        // This is the realistic tamper: decode payload, change "reader" -> "admin",
        // re-encode, leave the original signature untouched.
        RunAttack("Privilege escalation (edit role, reuse signature)",
            "Decode payload -> change role 'reader' to 'admin' -> re-encode -> keep the captured signature. The classic 'just edit the JSON' forgery.",
            () => honestValidator.Validate(EscalateRole(captured)));

        // (2) Algorithm-confusion / "alg: none" substitution.
        // Swap the header for {"alg":"none"} and drop the signature — the classic
        // JWT downgrade. The validator never trusts the token's alg to pick a path.
        RunAttack("Algorithm confusion ('alg: none')",
            "Replace the header with {\"alg\":\"none\"} and strip the signature, hoping the verifier honors it.",
            () => honestValidator.Validate(ForgeAlgNone(captured)));

        // (3) Wrong signing key (attacker mints their own token with their own key).
        using var attackerKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        string forged = new PqJwtBuilder()
            .WithSubject("alice").WithClaim("role", "admin")
            .WithLifetime(TimeSpan.FromMinutes(15)).SignWith(attackerKey).Build();
        RunAttack("Forged with attacker's own key",
            "Mint a fresh 'admin' token signed with a key the attacker controls.",
            () => honestValidator.Validate(forged));

        // (4) Expired token.
        string expired = new PqJwtBuilder()
            .WithSubject("alice")
            .WithExpiration(DateTimeOffset.UtcNow.AddMinutes(-10))
            .WithNotBefore(DateTimeOffset.UtcNow.AddMinutes(-20))
            .SignWith(_signingKey!).Build();
        RunAttack("Replay an expired token",
            "Present a properly-signed token whose lifetime has already passed.",
            () => honestValidator.Validate(expired));

        // (5) Missing required 'exp'.
        string noExp = new PqJwtBuilder()
            .WithSubject("alice").WithClaim("role", "reader")
            .SignWith(_signingKey!).Build();
        RunAttack("Token with no expiry",
            "Issue a signed token that omits 'exp', hoping it is treated as eternal.",
            () => honestValidator.Validate(noExp));

        // (6) Replay of a valid, unexpired token.
        var replayValidator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verificationKey,
            ReplayCache = new InMemoryReplayCache(),
            RequireReplayProtection = true,
        });
        string jtiTok = new PqJwtBuilder()
            .WithSubject("alice").WithLifetime(TimeSpan.FromMinutes(5))
            .WithJwtId(Guid.NewGuid().ToString("N")).SignWith(_signingKey!).Build();
        try { replayValidator.Validate(jtiTok); } catch { /* first use legitimately passes */ }
        RunAttack("Reuse a one-time token (replay)",
            "Submit the same valid token a second time after it was already accepted once.",
            () => replayValidator.Validate(jtiTok));

        AnsiConsole.MarkupLine("\n[dim]Every attempt above must say REJECTED. An ACCEPTED line would be a bug worth reporting.[/]");
    }

    private static void RunAttack(string title, string approach, Func<PqJwtValidationResult> attempt)
    {
        AnsiConsole.MarkupLine($"[bold]» {Markup.Escape(title)}[/]");
        AnsiConsole.MarkupLine($"  [dim]{Markup.Escape(approach)}[/]");
        try
        {
            attempt();
            AnsiConsole.MarkupLine("  [red]✗ ACCEPTED — this should not happen.[/]\n");
        }
        catch (PqJwtValidationException ex)
        {
            var (what, why) = RejectionExplainer.Explain(ex);
            AnsiConsole.MarkupLine($"  [green]✓ REJECTED[/] — [white]{Markup.Escape(what)}[/]");
            AnsiConsole.MarkupLine($"  [dim]{Markup.Escape(why)}[/]\n");
        }
    }

    // Realistic claim-level tamper: change role to "admin" but keep the signature.
    // Returns a structurally-valid 3-part token whose payload no longer matches
    // the signature — so the failure is "signature verification failed", the
    // exact lesson we want (not "malformed base64").
    private static string EscalateRole(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) return token;
        string payloadJson = DecodeSegment(parts[1]);
        using var doc = System.Text.Json.JsonDocument.Parse(payloadJson);
        var dict = new Dictionary<string, System.Text.Json.JsonElement>();
        foreach (var p in doc.RootElement.EnumerateObject()) dict[p.Name] = p.Value.Clone();
        // Overwrite the role claim with a privileged value.
        using var adminDoc = System.Text.Json.JsonDocument.Parse("\"admin\"");
        dict["role"] = adminDoc.RootElement.Clone();
        string mutated = System.Text.Json.JsonSerializer.Serialize(dict);
        parts[1] = EncodeSegment(mutated);   // signature (parts[2]) is left intact
        return string.Join('.', parts);
    }

    // Classic "alg: none" downgrade: header says no signature, third segment empty.
    private static string ForgeAlgNone(string token)
    {
        var parts = token.Split('.');
        if (parts.Length < 2) return token;
        parts[0] = EncodeSegment("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        // Keep payload, drop the signature entirely.
        return parts[0] + "." + parts[1] + ".";
    }

    private static string DecodeSegment(string seg)
    {
        string s = seg.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; }
        return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(s));
    }

    private static string EncodeSegment(string text)
    {
        var b = System.Text.Encoding.UTF8.GetBytes(text);
        return Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    // ── 8. Show keys ─────────────────────────────────────────────────────
    private static void ShowCurrentKeys()
    {
        if (_verificationKey is null)
        {
            AnsiConsole.MarkupLine("[yellow]No keys generated yet.[/]");
            return;
        }
        var pub = Convert.ToBase64String(_verificationKey.ExportMLDsaPublicKey());
        var t = new Table().Border(TableBorder.Rounded).AddColumn("Key").AddColumn("Algorithm").AddColumn("Public (base64, truncated)");
        t.AddRow("ML-DSA verification", "ML-DSA-65", pub[..32] + "…");
        if (_recipientKey is not null)
        {
            var xpub = Convert.ToBase64String(_recipientKey.PublicKey.Export());
            t.AddRow("X-Wing recipient", "X-Wing", xpub[..32] + "…");
        }
        AnsiConsole.Write(t);
        AnsiConsole.MarkupLine($"\n[dim]Active signing kid: [yellow]{_signingKid}[/][/]");
    }

    // ── 9. Security notes ────────────────────────────────────────────────
    private static void ShowSecurityNotes()
    {
        AnsiConsole.Write(new Rule("[bold red]Security notes & limitations (preview)[/]").RuleStyle("red"));
        AnsiConsole.Write(new Panel(
            "• [bold]Preview software, not audited.[/] API and wire format may change before 1.0.\n" +
            "• Native .NET 10 BCL primitives: ML-DSA-65 (FIPS 204), ML-KEM-768 (FIPS 203). X25519 + SHA3-256 via BouncyCastle.\n" +
            "• [bold]Non-standardized profile[/]: ML-DSA-65 / A256GCM are registered JOSE identifiers, but the X-Wing key-management profile is not — tokens will NOT validate in generic JWT tooling.\n" +
            "• Fail-closed: any validation failure throws PqJwtValidationException. No alg:none, no unsigned path.\n" +
            "• Replay protection requires a shared cache across all validating nodes.\n" +
            "• X-Wing encryption is one recipient per token.\n" +
            "• Signed token ≈ 4.5 KB; encrypted ≈ 6.5 KB — fine for Authorization headers, likely too big for cookies.")
            .Border(BoxBorder.Rounded).Padding(1, 1));
        AnsiConsole.MarkupLine("\n[dim]Full detail: KNOWN-GAPS.md and SECURITY.md in the repository.[/]");
    }

    // ── helpers ──────────────────────────────────────────────────────────
    private static bool RequireKeys()
    {
        if (_signingKey is not null && _verificationKey is not null) return true;
        AnsiConsole.MarkupLine("[red]No keys in session. Generate a keypair first (option 1).[/]");
        return false;
    }

    private static void DisposeKeys()
    {
        _signingKey?.Dispose();
        _verificationKey?.Dispose();
        _recipientKey?.Dispose();
        _signingKey = _verificationKey = null;
        _recipientKey = null;
    }
}
