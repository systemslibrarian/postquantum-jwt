using System.Security.Cryptography;
using FsCheck.Xunit;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// A <see cref="FactAttribute"/> that skips itself when the runtime lacks native
/// ML-KEM / ML-DSA support (these require OpenSSL 3.5+ on Linux). Tests stay
/// honest: they run and pass on a capable host, and show as skipped — with a
/// reason — everywhere else, rather than silently passing.
/// </summary>
public sealed class PqcFactAttribute : FactAttribute
{
    public PqcFactAttribute()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported)
        {
            Skip = "Requires native ML-KEM / ML-DSA support (OpenSSL 3.5+).";
        }
    }
}

/// <summary>The <see cref="TheoryAttribute"/> counterpart of <see cref="PqcFactAttribute"/>.</summary>
public sealed class PqcTheoryAttribute : TheoryAttribute
{
    public PqcTheoryAttribute()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported)
        {
            Skip = "Requires native ML-KEM / ML-DSA support (OpenSSL 3.5+).";
        }
    }
}

/// <summary>
/// Wraps FsCheck's <see cref="PropertyAttribute"/> so the property is skipped
/// (with a clear reason) on hosts that lack native ML-KEM / ML-DSA — the
/// property-based counterpart of <see cref="PqcFactAttribute"/>.
/// </summary>
public sealed class PqcPropertyAttribute : PropertyAttribute
{
    public PqcPropertyAttribute()
    {
        if (!MLKem.IsSupported || !MLDsa.IsSupported)
        {
            Skip = "Requires native ML-KEM / ML-DSA support (OpenSSL 3.5+).";
        }
    }
}

/// <summary>A deterministic clock for lifetime tests.</summary>
internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => now;
}

/// <summary>A test clock whose current time can be advanced.</summary>
internal sealed class MutableTimeProvider(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

internal static class TestKeys
{
    /// <summary>Generates an ML-DSA-65 signing key.</summary>
    public static MLDsa NewSigningKey() => MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

    /// <summary>Exports the public half of a signing key as a standalone verification key.</summary>
    public static MLDsa PublicKeyOf(MLDsa signingKey) =>
        MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());
}
