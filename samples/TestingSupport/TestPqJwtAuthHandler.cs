// TestPqJwtAuthHandler
//
// A drop-in ASP.NET Core authentication handler for CONSUMERS of PostQuantum.Jwt
// to use in their OWN integration tests. It bypasses ML-DSA / X-Wing entirely and
// authenticates every request with a fixed, test-controlled set of claims.
//
// WHY: running real PQ crypto across hundreds of WebApplicationFactory tests is
// slow, and worse, the native primitives need OpenSSL 3.5+, which a CI runner may
// not have. Tests of YOUR [Authorize] endpoints shouldn't depend on that - they
// should exercise your authorization logic, not re-test the crypto (the library's
// own suite does that). This handler lets a test say "treat the caller as an admin"
// and get a 200/403 decision without a single signature operation.
//
// SAFETY: this authenticates EVERYONE as the configured principal. It must NEVER
// be registered outside a test host. Guard it behind your test environment.
//
// Shipped as a SAMPLE showing the pattern. To make it a real
// PostQuantum.Jwt.Testing NuGet package, lift this file into its own project - it
// depends only on ASP.NET Core auth, not on the crypto library.
//
// To God be the glory - 1 Corinthians 10:31.

using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PostQuantum.Jwt.Testing;

/// <summary>
/// Options for <see cref="TestPqJwtAuthHandler"/>: the claims every request gets.
/// </summary>
public sealed class TestPqJwtOptions : AuthenticationSchemeOptions
{
    /// <summary>Scheme name; mirrors the real PqJwtBearer scheme so [Authorize] works unchanged.</summary>
    public const string DefaultScheme = "PqJwtBearer";

    /// <summary>Claims assigned to the authenticated test principal.</summary>
    public IList<Claim> Claims { get; } = new List<Claim>
    {
        new("sub", "test-user"),
        new("role", "admin"),
    };

    /// <summary>
    /// When set, only requests carrying this header authenticate (others are
    /// anonymous), so you can exercise the 401 path too. Null = authenticate all.
    /// </summary>
    public string? RequireHeader { get; set; }

    /// <summary>
    /// Environment names under which this handler is permitted to run. The handler
    /// THROWS at construction outside these, so it can never silently authenticate
    /// everyone in production even if misregistered. Defaults to common test names.
    /// </summary>
    public ISet<string> AllowedEnvironments { get; } =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Test", "Testing", "IntegrationTest" };
}

/// <summary>
/// Authenticates requests with fixed claims and no cryptography. TEST HOSTS ONLY.
/// Register via <see cref="TestAuthExtensions.AddTestPqJwtBearer"/>.
/// </summary>
public sealed class TestPqJwtAuthHandler : AuthenticationHandler<TestPqJwtOptions>
{
    public TestPqJwtAuthHandler(
        IOptionsMonitor<TestPqJwtOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IWebHostEnvironment environment)
        : base(options, logger, encoder)
    {
        // Absolute safeguard: refuse to exist outside an allowed test environment.
        // This is belt-and-suspenders on top of "only register it in
        // ConfigureTestServices" — if it's ever wired into a real host, startup
        // fails loudly instead of authenticating every caller as admin.
        var allowed = options.CurrentValue.AllowedEnvironments;
        if (!allowed.Contains(environment.EnvironmentName))
        {
            throw new InvalidOperationException(
                $"TestPqJwtAuthHandler must not run in environment '{environment.EnvironmentName}'. " +
                $"It authenticates every request with fixed claims and is for test hosts only. " +
                $"Allowed: {string.Join(", ", allowed)}.");
        }
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (Options.RequireHeader is { } header && !Request.Headers.ContainsKey(header))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var identity = new ClaimsIdentity(Options.Claims, Scheme.Name, nameType: "sub", roleType: "role");
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}

/// <summary>Registration helper for the test handler.</summary>
public static class TestAuthExtensions
{
    /// <summary>
    /// Registers the no-crypto test handler under the PqJwtBearer scheme name so
    /// existing <c>[Authorize]</c> attributes light up in tests unchanged.
    /// </summary>
    public static AuthenticationBuilder AddTestPqJwtBearer(
        this AuthenticationBuilder builder,
        Action<TestPqJwtOptions>? configure = null)
        => builder.AddScheme<TestPqJwtOptions, TestPqJwtAuthHandler>(
            TestPqJwtOptions.DefaultScheme, configure ?? (_ => { }));
}
