using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace PostQuantum.Jwt.Analyzers;

/// <summary>
/// PQJWT002 — flags constructing a <c>PqJwtValidator</c> and validating with it in
/// one expression (<c>new PqJwtValidator(...).Validate(...)</c>), which constructs a
/// fresh validator on every call. The validator is immutable and thread-safe and
/// should be created once and reused; per-call construction wastes work and, because
/// post-quantum signature verification is comparatively expensive, amplifies the cost
/// of every request.
/// </summary>
/// <remarks>
/// Deliberately precise: it fires only on the provably per-call inline form, so it
/// does NOT flag the correct patterns — a cached field, a static, or a DI
/// registration such as <c>AddSingleton(new PqJwtValidator(...))</c> — where the
/// instance is stored rather than validated inline.
/// </remarks>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ValidatorReuseAnalyzer : DiagnosticAnalyzer
{
    /// <summary>The diagnostic id for the per-call construction rule.</summary>
    public const string DiagnosticId = "PQJWT002";

    private const string HelpLink =
        "https://github.com/systemslibrarian/postquantum-jwt/blob/main/docs/SECURITY-AUDIT-TOOLS.md";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Reuse a single PqJwtValidator instance",
        messageFormat: "Constructing a PqJwtValidator per validation is wasteful and amplifies post-quantum verification cost. Create one instance (a field, singleton, or DI registration) — it is immutable and thread-safe — and reuse it.",
        category: "Performance",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true,
        description: "PqJwtValidator is immutable and thread-safe; construct it once and reuse it rather than per request.",
        helpLinkUri: HelpLink);

    /// <inheritdoc />
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    /// <inheritdoc />
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(start =>
        {
            var validatorType = start.Compilation.GetTypeByMetadataName("PostQuantum.Jwt.PqJwtValidator");
            if (validatorType is null)
            {
                return;
            }

            start.RegisterOperationAction(ctx => AnalyzeInvocation(ctx, validatorType), OperationKind.Invocation);
        });
    }

    private static void AnalyzeInvocation(OperationAnalysisContext context, INamedTypeSymbol validatorType)
    {
        var invocation = (IInvocationOperation)context.Operation;
        if (invocation.TargetMethod.Name != "Validate")
        {
            return;
        }

        var instance = invocation.Instance;
        if (instance is IConversionOperation conversion)
        {
            instance = conversion.Operand;
        }

        if (instance is IObjectCreationOperation creation &&
            SymbolEqualityComparer.Default.Equals(creation.Type, validatorType))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, creation.Syntax.GetLocation()));
        }
    }
}
