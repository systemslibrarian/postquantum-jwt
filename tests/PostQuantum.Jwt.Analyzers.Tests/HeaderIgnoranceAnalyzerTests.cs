using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;
using PostQuantum.Jwt.Analyzers;
using Xunit;

namespace PostQuantum.Jwt.Analyzers.Tests;

public class HeaderIgnoranceAnalyzerTests
{
    private static Task VerifyAsync(string source)
    {
        var test = new CSharpAnalyzerTest<HeaderIgnoranceAnalyzer, DefaultVerifier>
        {
            TestCode = source,
            ReferenceAssemblies = ReferenceAssemblies.Net.Net80,
        };
        return test.RunAsync();
    }

    // ── PQJWT001 fires (prohibited header inspection) ──────────────────────

    [Fact]
    public Task GetProperty_alg_is_flagged() => VerifyAsync("""
        using System.Text.Json;
        class C { JsonElement M(JsonElement h) => {|PQJWT001:h.GetProperty("alg")|}; }
        """);

    [Fact]
    public Task TryGetProperty_jwk_is_flagged() => VerifyAsync("""
        using System.Text.Json;
        class C { bool M(JsonElement h) => {|PQJWT001:h.TryGetProperty("jwk", out _)|}; }
        """);

    [Fact]
    public Task JsonNode_indexer_jku_is_flagged() => VerifyAsync("""
        using System.Text.Json.Nodes;
        class C { JsonNode? M(JsonObject o) => {|PQJWT001:o["jku"]|}; }
        """);

    [Fact]
    public Task X5c_and_x5u_are_flagged() => VerifyAsync("""
        using System.Text.Json;
        class C
        {
            JsonElement A(JsonElement h) => {|PQJWT001:h.GetProperty("x5c")|};
            JsonElement B(JsonElement h) => {|PQJWT001:h.GetProperty("x5u")|};
        }
        """);

    // ── PQJWT001 stays quiet (no false positives) ──────────────────────────

    [Fact]
    public Task Non_prohibited_field_is_not_flagged() => VerifyAsync("""
        using System.Text.Json;
        class C { string? M(JsonElement h) => h.GetProperty("sub").GetString(); }
        """);

    [Fact]
    public Task Plain_dictionary_with_alg_key_is_not_flagged() => VerifyAsync("""
        using System.Collections.Generic;
        class C { string M(IDictionary<string, string> d) => d["alg"]; }
        """);

    [Fact]
    public Task PqJwt_result_claim_named_alg_is_not_flagged() => VerifyAsync("""
        class Result { public string GetString(string n) => n; }
        class C { string M(Result r) => r.GetString("alg"); }
        """);
}
