using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace PostQuantum.Jwt.Analyzers;

/// <summary>
/// PQJWT001 — flags reading a prohibited JOSE header field (<c>alg</c>, <c>jwk</c>,
/// <c>jku</c>, <c>x5u</c>, <c>x5c</c>) out of a parsed JSON object. PostQuantum.Jwt
/// resolves the verification key from a trusted, internal key ring keyed by
/// <c>kid</c> — never from the token's header — so consumer code should never need
/// to inspect these fields. Doing so reintroduces the header-driven key-selection
/// attacks (algorithm confusion, <c>jwk</c>/<c>jku</c> key injection) the library
/// eliminates by design.
/// </summary>
/// <remarks>
/// Semantic, not textual: it matches only a <see cref="System.Text.Json"/> access —
/// <c>JsonElement.GetProperty/TryGetProperty("alg")</c> or a <c>JsonNode</c>/
/// <c>JsonObject</c> indexer <c>["alg"]</c> — so it does not false-positive on
/// unrelated dictionaries or configuration that merely happen to use such a key.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class HeaderIgnoranceAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The diagnostic id for the prohibited-header-inspection rule.</summary>
    public const string DiagnosticId = "PQJWT001";

    private const string HelpLink =
        "https://github.com/systemslibrarian/postquantum-jwt/blob/main/docs/SECURITY-AUDIT-TOOLS.md";

    private static readonly ImmutableHashSet<string> ProhibitedFields =
        ImmutableHashSet.Create("alg", "jwk", "jku", "x5u", "x5c");

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Token header field must not be inspected",
        messageFormat: "Reading the JOSE header field '{0}' is prohibited: PostQuantum.Jwt resolves the verification key from a trusted key ring, never from the token header. Call PqJwtValidator.Validate(...) instead of inspecting the header.",
        category: "Security",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true,
        description: "The verification path must not depend on attacker-controlled header fields (alg/jwk/jku/x5u/x5c); resolve keys from an internal key ring keyed by kid.",
        helpLinkUri: HelpLink);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(OnCompilationStart);
    }

    private static void OnCompilationStart(CompilationStartAnalysisContext context)
    {
        var jsonElement = context.Compilation.GetTypeByMetadataName("System.Text.Json.JsonElement");
        var jsonNode = context.Compilation.GetTypeByMetadataName("System.Text.Json.Nodes.JsonNode");

        // Without System.Text.Json there is nothing this rule can match.
        if (jsonElement is null && jsonNode is null)
        {
            return;
        }

        if (jsonElement is not null)
        {
            context.RegisterOperationAction(ctx => AnalyzeInvocation(ctx, jsonElement), OperationKind.Invocation);
        }

        if (jsonNode is not null)
        {
            context.RegisterOperationAction(ctx => AnalyzePropertyReference(ctx, jsonNode), OperationKind.PropertyReference);
        }
    }

    // JsonElement.GetProperty("alg") / TryGetProperty("alg", out _)
    private static void AnalyzeInvocation(OperationAnalysisContext context, INamedTypeSymbol jsonElement)
    {
        var invocation = (IInvocationOperation)context.Operation;
        var method = invocation.TargetMethod;

        if (!SymbolEqualityComparer.Default.Equals(method.ContainingType, jsonElement))
        {
            return;
        }

        if (method.Name is not ("GetProperty" or "TryGetProperty") || invocation.Arguments.Length == 0)
        {
            return;
        }

        ReportIfProhibited(context, invocation.Arguments[0].Value, invocation.Syntax);
    }

    // JsonNode / JsonObject indexer: node["alg"]
    private static void AnalyzePropertyReference(OperationAnalysisContext context, INamedTypeSymbol jsonNode)
    {
        var reference = (IPropertyReferenceOperation)context.Operation;

        if (!reference.Property.IsIndexer ||
            !InheritsFromOrEquals(reference.Property.ContainingType, jsonNode) ||
            reference.Arguments.Length == 0)
        {
            return;
        }

        ReportIfProhibited(context, reference.Arguments[0].Value, reference.Syntax);
    }

    private static void ReportIfProhibited(OperationAnalysisContext context, IOperation argument, SyntaxNode syntax)
    {
        var constant = argument.ConstantValue;
        if (constant.HasValue && constant.Value is string name && ProhibitedFields.Contains(name))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, syntax.GetLocation(), name));
        }
    }

    private static bool InheritsFromOrEquals(INamedTypeSymbol? type, INamedTypeSymbol baseType)
    {
        for (var current = type; current is not null; current = current.BaseType)
        {
            if (SymbolEqualityComparer.Default.Equals(current, baseType))
            {
                return true;
            }
        }

        return false;
    }
}
