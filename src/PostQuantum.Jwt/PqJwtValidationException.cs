namespace PostQuantum.Jwt;

/// <summary>
/// Thrown when a token fails validation. PostQuantum.Jwt is <b>fail-closed</b>:
/// any verification failure — a bad signature, a tampered token, an expired or
/// not-yet-valid token, or a claim mismatch — surfaces as this exception rather
/// than a partial or "best effort" result.
/// </summary>
public sealed class PqJwtValidationException : PqJwtException
{
    /// <summary>Initializes a new instance of the <see cref="PqJwtValidationException"/> class.</summary>
    public PqJwtValidationException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="PqJwtValidationException"/> class.</summary>
    /// <param name="message">A description of why validation failed.</param>
    public PqJwtValidationException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="PqJwtValidationException"/> class.</summary>
    /// <param name="message">A description of why validation failed.</param>
    /// <param name="innerException">The underlying cause.</param>
    public PqJwtValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
