// PqJwtPlayground — Blazor Server host.
//
// Blazor Server (not WASM) is deliberate: the ML-DSA / ML-KEM primitives need a
// real .NET 10 runtime with OpenSSL 3.5+ and do not run in the browser. All
// crypto executes server-side; private keys never leave the server.
//
// To God be the glory - 1 Corinthians 10:31.

using PostQuantum.Jwt.Playground.Components;
using PostQuantum.Jwt.Playground.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddSingleton<PqJwtDemoService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

app.Run();
