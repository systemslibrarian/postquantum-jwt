# Test support: authenticate without crypto

A test-only ASP.NET Core auth handler so **consumers** of PostQuantum.Jwt can
test their own `[Authorize]` endpoints without running ML-DSA / X-Wing — fast,
and without needing OpenSSL 3.5+ on the CI runner.

## Use it in a WebApplicationFactory test

```csharp
public class MyApiTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public MyApiTests(WebApplicationFactory<Program> factory) =>
        _factory = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.AddAuthentication(TestPqJwtOptions.DefaultScheme)
                    .AddTestPqJwtBearer(o =>
                    {
                        o.Claims.Clear();
                        o.Claims.Add(new("sub", "alice"));
                        o.Claims.Add(new("role", "admin"));   // make the caller an admin
                    });
        }));

    [Fact]
    public async Task Admin_endpoint_allows_admin()
    {
        var resp = await _factory.CreateClient().GetAsync("/admin");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}
```

To test the **401 path**, set `o.RequireHeader = "X-Test-Auth"` and omit that
header on the request.

## Safety

This handler authenticates **every** request (or every one with the configured
header) as the fixed principal. **Never register it outside a test host.**

As an absolute safeguard it injects `IWebHostEnvironment` and **throws at
construction** if the environment isn't in `AllowedEnvironments` (defaults:
`Test`, `Testing`, `IntegrationTest`). So even if it's accidentally wired into a
real host, startup fails loudly instead of silently authenticating everyone as
admin. Set your test host's environment accordingly (e.g.
`builder.UseEnvironment("Test")` in your `WebApplicationFactory`).

> This is a sample of the pattern. It depends only on ASP.NET Core auth, not the
> crypto library, so it's a clean candidate to lift into a published
> `PostQuantum.Jwt.Testing` package if you want one.

---

*To God be the glory — 1 Corinthians 10:31.*
