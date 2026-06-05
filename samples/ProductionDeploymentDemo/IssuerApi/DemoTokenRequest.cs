namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.IssuerApi;

public sealed record DemoTokenRequest(
    string? Subject,
    string? Role,
    string? Scope,
    int? LifetimeSeconds,
    bool? Encrypted);
