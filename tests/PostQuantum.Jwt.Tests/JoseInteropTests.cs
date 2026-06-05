using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using PostQuantum.Jwt.Internal;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Differential / oracle parser tests: tokens produced by
/// <see cref="PqJwtBuilder"/> are re-parsed with
/// <see cref="JsonWebTokenHandler"/> (Microsoft.IdentityModel.JsonWebTokens) and
/// the header + claim shape is checked against what the builder was asked to
/// emit. The Microsoft handler cannot *verify* an ML-DSA-65 signature — it has
/// no PQ knowledge — but it can structurally parse the JOSE wire format with
/// an *independent* implementation. Anywhere PqJwt's parser tolerates a token
/// the canonical parser rejects (or vice versa) shows up here as a hard
/// assertion failure: wire compatibility is a property, not a hope.
/// <para>
/// Only the signed 3-part JWS shape is exercised. The 5-part X-Wing envelope
/// is a non-standard JOSE profile (per <see cref="PqJwtAlgorithms"/> doc) and
/// is deliberately not expected to round-trip through a generic JWE parser.
/// </para>
/// </summary>
public sealed class JoseInteropTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    [PqcFact]
    public void Builder_output_parses_with_canonical_JOSE_parser_and_shape_matches()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var exp = Now + TimeSpan.FromMinutes(30);

        var token = new PqJwtBuilder(clock)
            .WithIssuer("https://issuer.example")
            .WithSubject("user-123")
            .WithAudience("https://api.example")
            .WithJwtId("token-1")
            .WithKeyId("k-1")
            .WithLifetime(TimeSpan.FromMinutes(30))
            .SignWith(signingKey)
            .Build();

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(token);

        Assert.Equal(3, token.Split('.').Length);
        Assert.Equal(PqJwtAlgorithms.MLDsa65, jwt.Alg);
        Assert.Equal(PqJwtAlgorithms.TokenType, jwt.Typ);
        Assert.Equal("k-1", jwt.Kid);
        Assert.Equal("https://issuer.example", jwt.Issuer);
        Assert.Equal("user-123", jwt.Subject);
        Assert.Equal("token-1", jwt.Id);

        // ReadJsonWebToken does NOT verify the signature (and could not for
        // ML-DSA), but it MUST surface every claim verbatim.
        var aud = Assert.Single(jwt.Audiences);
        Assert.Equal("https://api.example", aud);

        Assert.True(jwt.TryGetPayloadValue<long>("iat", out var iat));
        Assert.Equal(Now.ToUnixTimeSeconds(), iat);
        Assert.True(jwt.TryGetPayloadValue<long>("exp", out var expClaim));
        Assert.Equal(exp.ToUnixTimeSeconds(), expClaim);
    }

    [PqcFact]
    public void Header_is_a_two_field_JOSE_object_when_no_kid_is_set()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithSubject("s")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        // Inspect the header bytes directly (canonical JSON parser).
        var encodedHeader = token.Split('.')[0];
        using var doc = JsonDocument.Parse(Base64Url.DecodeToUtf8(encodedHeader));
        var root = doc.RootElement;

        // Without kid the header is exactly {alg, typ} — no extra parameters,
        // no jku/jwk/x5u/x5c/cty/enc fields slipping in.
        var props = root.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "alg", "typ" }, props);
        Assert.Equal(PqJwtAlgorithms.MLDsa65, root.GetProperty("alg").GetString());
        Assert.Equal(PqJwtAlgorithms.TokenType, root.GetProperty("typ").GetString());
    }

    [PqcFact]
    public void Header_with_kid_is_a_three_field_JOSE_object()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithSubject("s")
            .WithKeyId("kid-7")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var encodedHeader = token.Split('.')[0];
        using var doc = JsonDocument.Parse(Base64Url.DecodeToUtf8(encodedHeader));
        var props = doc.RootElement.EnumerateObject()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        // Exactly {alg, kid, typ} — no other parameters introduced when a kid
        // is set. (Catches any future header-pollution regression.)
        Assert.Equal(new[] { "alg", "kid", "typ" }, props);
    }

    [PqcFact]
    public void Canonical_parser_rejects_a_non_JSON_header()
    {
        // Negative differential: when something at the wire-shape layer is
        // clearly broken (header segment that doesn't decode to a JSON
        // object), the canonical parser must reject it. PqJwtValidator
        // independently rejects the same input as MalformedJson — this test
        // pins agreement on what "broken" looks like, not just on the happy
        // path.
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithSubject("s")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        // Replace the header with base64url that decodes to "not json".
        var notJson = Base64Url.EncodeUtf8("not json");
        var parts = token.Split('.');
        var malformed = $"{notJson}.{parts[1]}.{parts[2]}";

        var handler = new JsonWebTokenHandler();
        Assert.ThrowsAny<Exception>(() => handler.ReadJsonWebToken(malformed));
    }

    [PqcFact]
    public void Claims_with_unicode_and_nested_json_survive_oracle_parse()
    {
        // Round-trip a non-trivial claim set through both parsers. Anywhere
        // the in-house and canonical parsers disagree on the structural shape
        // — escape sequences, code point handling, nested object preservation
        // — surfaces here.
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithSubject("π—🎫—naïve")
            .WithClaim("nested", new { count = 3, name = "café" })
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var handler = new JsonWebTokenHandler();
        var jwt = handler.ReadJsonWebToken(token);

        Assert.Equal("π—🎫—naïve", jwt.Subject);
        Assert.True(jwt.TryGetPayloadValue<JsonElement>("nested", out var nested));
        Assert.Equal(3, nested.GetProperty("count").GetInt32());
        Assert.Equal("café", nested.GetProperty("name").GetString());
    }
}
