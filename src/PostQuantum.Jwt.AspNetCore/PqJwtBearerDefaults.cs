namespace PostQuantum.Jwt.AspNetCore;

/// <summary>
/// Well-known constants for the post-quantum JWT bearer authentication scheme.
/// </summary>
public static class PqJwtBearerDefaults
{
    /// <summary>
    /// The default authentication scheme name. Use this as the
    /// <see cref="Microsoft.AspNetCore.Authentication.AuthenticationOptions.DefaultScheme"/>
    /// or with <c>[Authorize(AuthenticationSchemes = PqJwtBearerDefaults.AuthenticationScheme)]</c>.
    /// </summary>
    public const string AuthenticationScheme = "PqJwtBearer";

    /// <summary>The Authorization header scheme this handler expects (<c>Bearer</c>).</summary>
    public const string BearerPrefix = "Bearer ";
}
