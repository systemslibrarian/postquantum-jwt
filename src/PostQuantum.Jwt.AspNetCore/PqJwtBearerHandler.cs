using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PostQuantum.Jwt.AspNetCore;

/// <summary>
/// An <see cref="AuthenticationHandler{TOptions}"/> that validates incoming
/// <c>Authorization: Bearer …</c> tokens with <see cref="PqJwtValidator"/>.
/// Fail-closed: any token that fails validation produces
/// <see cref="AuthenticateResult.Fail(Exception)"/>; bypasses the standard
/// <c>JwtBearerHandler</c> entirely so consumers don't have to teach
/// <c>Microsoft.IdentityModel</c> about <c>ML-DSA-65</c>.
/// </summary>
public sealed class PqJwtBearerHandler : AuthenticationHandler<PqJwtBearerOptions>
{
    private PqJwtValidator? _validator;
    private PqJwtValidationParameters? _validatorParameters;

    /// <summary>Creates the handler.</summary>
    /// <param name="options">The options monitor (DI-supplied).</param>
    /// <param name="logger">A logger factory (DI-supplied).</param>
    /// <param name="encoder">A URL encoder (DI-supplied).</param>
    public PqJwtBearerHandler(
        IOptionsMonitor<PqJwtBearerOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
        // Defer validator construction to first use — base.Options is not
        // populated until InitializeAsync runs the named-options lookup.
    }

    private PqJwtValidator Validator
    {
        get
        {
            // Cheap reference-equality short-circuit: as long as the options
            // instance hasn't changed (IOptionsMonitor reload), keep the
            // existing validator.
            var current = Options.ValidationParameters;
            if (_validator is null || !ReferenceEquals(_validatorParameters, current))
            {
                _validator = new PqJwtValidator(current, Options.TimeProvider);
                _validatorParameters = current;
            }

            return _validator;
        }
    }

    /// <inheritdoc />
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // No header / wrong scheme → "no result" rather than "fail": lets other
        // schemes get a shot at the request.
        var authorization = Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authorization) ||
            !authorization.StartsWith(PqJwtBearerDefaults.BearerPrefix, StringComparison.Ordinal))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var token = authorization[PqJwtBearerDefaults.BearerPrefix.Length..];

        PqJwtValidationResult result;
        try
        {
            result = Validator.Validate(token);
        }
        catch (PqJwtValidationException ex)
        {
            // Fail-closed: tampered / expired / wrong-issuer tokens.
            Logger.ValidationFailed(ex);
            return Task.FromResult(AuthenticateResult.Fail(ex));
        }

        var identity = new ClaimsIdentity(
            authenticationType: Options.AuthenticationType,
            nameType: Options.NameClaimType,
            roleType: Options.RoleClaimType);

        // Project the validated claims onto Claim objects. Each JSON value is
        // emitted as a string; arrays are flattened into one Claim per item so
        // [Authorize(Roles="…,…")] works against a typical role-array claim.
        foreach (var (name, element) in result.Claims)
        {
            AppendClaim(identity, name, element);
        }

        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    private static void AppendClaim(ClaimsIdentity identity, string name, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                identity.AddClaim(new Claim(name, element.GetString() ?? string.Empty));
                break;
            case JsonValueKind.Number:
                identity.AddClaim(new Claim(name, element.GetRawText()));
                break;
            case JsonValueKind.True:
            case JsonValueKind.False:
                identity.AddClaim(new Claim(name, element.GetBoolean() ? "true" : "false"));
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                {
                    AppendClaim(identity, name, item);
                }

                break;
            case JsonValueKind.Object:
                identity.AddClaim(new Claim(name, element.GetRawText(), "application/json"));
                break;
            case JsonValueKind.Null:
            case JsonValueKind.Undefined:
            default:
                // Skip — null/undefined claims add no information.
                break;
        }
    }

    /// <inheritdoc />
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate =
            $"Bearer realm=\"{Options.ClaimsIssuer ?? Scheme.Name}\"";
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
