using Microsoft.AspNetCore.Authentication;

namespace PostQuantum.Jwt.AspNetCore;

/// <summary>
/// Options for the <see cref="PqJwtBearerHandler"/>. The handler delegates token
/// validation to <see cref="PqJwtValidator"/>; this class supplies the validation
/// parameters and a few ASP.NET-Core-specific knobs.
/// </summary>
public sealed class PqJwtBearerOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// The validation parameters PostQuantum.Jwt uses to verify incoming tokens.
    /// Required.
    /// </summary>
    public PqJwtValidationParameters ValidationParameters { get; set; } = new();

    /// <summary>
    /// The claim type that <see cref="System.Security.Claims.ClaimsIdentity.Name"/>
    /// is sourced from. Defaults to <c>"sub"</c> (the JWT subject claim) which is
    /// what most JWT consumers expect — <c>Microsoft.AspNetCore.Authentication.JwtBearer</c>
    /// defaults to <c>"unique_name"</c>, which is less portable.
    /// </summary>
    public string NameClaimType { get; set; } = "sub";

    /// <summary>
    /// The claim type used for role checks (<c>[Authorize(Roles=…)]</c>). Defaults
    /// to <c>"role"</c>, matching common ML-DSA-issued tokens.
    /// </summary>
    public string RoleClaimType { get; set; } = "role";

    /// <summary>
    /// The authentication type used for the constructed <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// Defaults to <see cref="PqJwtBearerDefaults.AuthenticationScheme"/> so
    /// <c>User.Identity.IsAuthenticated</c> behaves correctly.
    /// </summary>
    public string AuthenticationType { get; set; } = PqJwtBearerDefaults.AuthenticationScheme;

    // Clock comes from the inherited AuthenticationSchemeOptions.TimeProvider —
    // set it on Options if you need a deterministic clock for tests or for
    // simulated time in production.
}
