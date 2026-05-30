namespace PostQuantum.Jwt;

/// <summary>
/// Thrown for configuration or usage errors when building or validating tokens
/// (for example, a missing signing key or a malformed token structure).
/// </summary>
public class PqJwtException : Exception
{
    /// <summary>Initializes a new instance of the <see cref="PqJwtException"/> class.</summary>
    public PqJwtException()
    {
    }

    /// <summary>Initializes a new instance of the <see cref="PqJwtException"/> class.</summary>
    /// <param name="message">A description of the error.</param>
    public PqJwtException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="PqJwtException"/> class.</summary>
    /// <param name="message">A description of the error.</param>
    /// <param name="innerException">The underlying cause.</param>
    public PqJwtException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
