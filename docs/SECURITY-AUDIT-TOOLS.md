# PostQuantum.Jwt Security Audit Tools

Securing post-quantum infrastructure requires strict, enforceable boundaries. Because `PostQuantum.Jwt` deliberately breaks away from classical, IANA-standard JWT behaviors (like symmetric HMACs and header-driven algorithm selection) to enforce ML-DSA-65, standard security scanners will generate false positives or miss critical architectural flaws entirely.

To ensure your implementation remains secure and fail-closed, we provide two methods for auditing your code:

1. **Static Analysis (Roslyn Analyzer):** For real-time, deterministic compile-time enforcement of API boundaries.
2. **AI Semantic Audit (System Prompt):** For context-aware, architectural review of your validation sequencing and telemetry.

We strongly recommend utilizing both.

---

## Method 1: The Roslyn Analyzer (Compile-Time Enforcement)

The `PostQuantum.Jwt.Analyzers` package plugs directly into the .NET compiler (Roslyn) and inspects your code as you type. It's a separate, opt-in package — add it as a build-only dependency:

```xml
<PackageReference Include="PostQuantum.Jwt.Analyzers" Version="1.0.0-preview.3" PrivateAssets="all" />
```

### What it catches

| Rule | Severity | Pattern |
| ---- | -------- | ------- |
| **PQJWT001** | Error | Reading a JOSE header field (`alg`, `jwk`, `jku`, `x5u`, `x5c`) from a `System.Text.Json` `JsonElement.GetProperty`/`TryGetProperty` or a `JsonNode`/`JsonObject` indexer. The verification key comes from a trusted key ring keyed by `kid`, never the token header. |
| **PQJWT002** | Warning | `new PqJwtValidator(...).Validate(...)` — constructing a validator per call instead of caching a single (immutable, thread-safe) instance. |

Both rules are **semantic** (type-aware via the Roslyn semantic model), so they don't false-positive on unrelated dictionaries/JSON or on the correct singleton/DI registration patterns. There is intentionally **no auto code-fix** — there's no safe mechanical rewrite for "stop inspecting the header" or "introduce a singleton," so the diagnostics carry a help link instead of silently changing your code.

Tune severity per project in `.editorconfig` (e.g. `dotnet_diagnostic.PQJWT001.severity = warning`), or suppress a justified case with `#pragma warning disable PQJWT001`.

*(Source and rule list: `src/Analyzers/PostQuantum.Jwt.Analyzers/`.)*

---

## Method 2: The AI Semantic Audit (Architectural Review)

While Roslyn is perfect for syntax, an AI agent is better suited for checking the semantic flow of your application (e.g., ensuring cheap checks happen before expensive post-quantum signature verification).

### How to use:
1. Provide the `docs/PQ-JWT-AUDIT-PROMPT.md` file to your preferred AI coding assistant or Codespace agent.
2. Instruct the AI to execute the audit against your current workspace or specific JWT validation classes.