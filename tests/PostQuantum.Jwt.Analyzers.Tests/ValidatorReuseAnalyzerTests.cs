using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Testing;
using PostQuantum.Jwt.Analyzers;
using Xunit;

namespace PostQuantum.Jwt.Analyzers.Tests;

public class ValidatorReuseAnalyzerTests
{
    // A minimal stand-in for the real type — the analyzer resolves it by metadata
    // name (PostQuantum.Jwt.PqJwtValidator), which matches a source-declared type.
    private const string Stub = """
        namespace PostQuantum.Jwt
        {
            public sealed class PqJwtValidator
            {
                public PqJwtValidator(object parameters) { }
                public object Validate(string token) => token;
            }
        }
        """;

    private static Task VerifyAsync(string source)
    {
        var test = new CSharpAnalyzerTest<ValidatorReuseAnalyzer, DefaultVerifier>
        {
            TestCode = source,
            ReferenceAssemblies = ReferenceAssemblies.Net.Net80,
        };
        // The stub type lives in its own source file so the consumer's `using`
        // ordering is unaffected.
        test.TestState.Sources.Add(("Stub.cs", Stub));
        return test.RunAsync();
    }

    // ── PQJWT002 fires (per-call construction) ─────────────────────────────

    [Fact]
    public Task Inline_construct_and_validate_is_flagged() => VerifyAsync("""
        using PostQuantum.Jwt;
        class C { object M(object p, string t) => {|PQJWT002:new PqJwtValidator(p)|}.Validate(t); }
        """);

    // ── PQJWT002 stays quiet (correct singleton / DI patterns) ─────────────

    [Fact]
    public Task Cached_field_instance_is_not_flagged() => VerifyAsync("""
        using PostQuantum.Jwt;
        class C
        {
            static readonly PqJwtValidator V = new PqJwtValidator(null!);
            object M(string t) => V.Validate(t);
        }
        """);

    [Fact]
    public Task Di_style_registration_is_not_flagged() => VerifyAsync("""
        using PostQuantum.Jwt;
        class C
        {
            void M(object p) => Register(new PqJwtValidator(p));
            static void Register(object instance) { }
        }
        """);

    [Fact]
    public Task Factory_returning_a_new_validator_is_not_flagged() => VerifyAsync("""
        using PostQuantum.Jwt;
        class C { PqJwtValidator Create(object p) => new PqJwtValidator(p); }
        """);
}
