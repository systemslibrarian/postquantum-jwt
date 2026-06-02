; Unshipped analyzer release
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

### New Rules

Rule ID  | Category    | Severity | Notes
---------|-------------|----------|-------------------------------------------------
PQJWT001 | Security    | Error    | HeaderIgnoranceAnalyzer: token header field must not be inspected.
PQJWT002 | Performance | Warning  | ValidatorReuseAnalyzer: reuse a single PqJwtValidator instance.
