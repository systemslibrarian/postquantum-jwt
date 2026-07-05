using Microsoft.AspNetCore.Authentication;

namespace PostQuantum.Jwt.AspNetCore;

/// <summary>
/// <c>AddPqJwtBearer(…)</c> extension methods for
/// <see cref="AuthenticationBuilder"/>. Mirrors the shape of
/// <c>AddJwtBearer</c> from
/// <c>Microsoft.AspNetCore.Authentication.JwtBearer</c> so it slots into
/// existing auth-pipeline configuration the same way.
/// </summary>
/// <remarks>
/// This package is superseded by <c>PostQuantum.AspNetCore</c>, where this
/// entry point continues as <c>AddPostQuantumJwtBearer(…)</c>. Tokens minted
/// under either package validate in the other. See the migration guide:
/// <see href="https://github.com/systemslibrarian/postquantum-aspnetcore/blob/main/docs/MIGRATION.md"/>.
/// </remarks>
public static class PqJwtBearerExtensions
{
    private const string SupersededMessage =
        "PostQuantum.Jwt.AspNetCore is superseded by PostQuantum.AspNetCore, where this " +
        "entry point continues as AddPostQuantumJwtBearer(). This package is frozen at " +
        "1.0.0 (critical fixes only). Migration guide: " +
        "https://github.com/systemslibrarian/postquantum-aspnetcore/blob/main/docs/MIGRATION.md";

    /// <summary>
    /// Adds post-quantum JWT bearer authentication under
    /// <see cref="PqJwtBearerDefaults.AuthenticationScheme"/> with default options.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configure">Callback to configure <see cref="PqJwtBearerOptions"/>.</param>
    /// <returns>The same <see cref="AuthenticationBuilder"/>.</returns>
    [Obsolete(SupersededMessage, DiagnosticId = "PQJWT100")]
    public static AuthenticationBuilder AddPqJwtBearer(
        this AuthenticationBuilder builder,
        Action<PqJwtBearerOptions> configure)
        => builder.AddPqJwtBearer(PqJwtBearerDefaults.AuthenticationScheme, configure);

    /// <summary>
    /// Adds post-quantum JWT bearer authentication under a custom scheme name.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The scheme name (e.g. <c>"PqJwtBearer"</c>).</param>
    /// <param name="configure">Callback to configure <see cref="PqJwtBearerOptions"/>.</param>
    /// <returns>The same <see cref="AuthenticationBuilder"/>.</returns>
    [Obsolete(SupersededMessage, DiagnosticId = "PQJWT100")]
    public static AuthenticationBuilder AddPqJwtBearer(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<PqJwtBearerOptions> configure)
        => builder.AddPqJwtBearer(authenticationScheme, displayName: null, configure);

    /// <summary>
    /// Adds post-quantum JWT bearer authentication under a custom scheme name
    /// and display name.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The scheme name.</param>
    /// <param name="displayName">An optional human-readable display name.</param>
    /// <param name="configure">Callback to configure <see cref="PqJwtBearerOptions"/>.</param>
    /// <returns>The same <see cref="AuthenticationBuilder"/>.</returns>
    [Obsolete(SupersededMessage, DiagnosticId = "PQJWT100")]
    public static AuthenticationBuilder AddPqJwtBearer(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        string? displayName,
        Action<PqJwtBearerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(authenticationScheme);
        ArgumentNullException.ThrowIfNull(configure);

        return builder.AddScheme<PqJwtBearerOptions, PqJwtBearerHandler>(
            authenticationScheme, displayName, configure);
    }
}
