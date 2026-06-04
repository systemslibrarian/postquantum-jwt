using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using PostQuantum.Jwt.Cryptography;

namespace PostQuantum.Jwt.Benchmarks;

/// <summary>
/// Warm-path throughput and allocation for the four hot operations: sign,
/// verify, sign-then-encrypt, and decrypt-and-verify. Keys and sample tokens are
/// built once in <see cref="Setup"/> so each measured method exercises only the
/// operation under test — not key generation.
/// </summary>
/// <remarks>
/// Expect the wall-clock here to be dominated by the native BCL lattice
/// operation (ML-DSA sign/verify, ML-KEM encaps/decaps). The surrounding
/// glue — Base64url, JSON, header assembly — is a rounding error against a
/// ~3.3 KB ML-DSA-65 signature. The point of measuring it is to make that
/// cost honest and visible, not to chase it.
/// </remarks>
[MemoryDiagnoser]
public class TokenBenchmarks
{
    // A lifetime long enough that the sample tokens never expire mid-run.
    private static readonly TimeSpan TokenLifetime = TimeSpan.FromDays(365);

    private MLDsa _signingKey = null!;
    private MLDsa _verificationKey = null!;
    private XWingPrivateKey _decryptionKey = null!;
    private PqJwtValidator _signedValidator = null!;
    private PqJwtValidator _encryptedValidator = null!;
    private string _signedToken = null!;
    private string _encryptedToken = null!;

    [GlobalSetup]
    public void Setup()
    {
        _signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        _verificationKey = MLDsa.ImportMLDsaPublicKey(
            MLDsaAlgorithm.MLDsa65, _signingKey.ExportMLDsaPublicKey());
        _decryptionKey = XWingPrivateKey.Generate();

        _signedValidator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verificationKey,
        });
        _encryptedValidator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = _verificationKey,
            DecryptionKey = _decryptionKey,
        });

        _signedToken = BuildSigned();
        _encryptedToken = BuildEncrypted();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _signingKey.Dispose();
        _verificationKey.Dispose();
        _decryptionKey.Dispose();
    }

    [Benchmark(Description = "Sign (ML-DSA-65)")]
    public string Sign() => BuildSigned();

    [Benchmark(Description = "Verify (ML-DSA-65)")]
    public PqJwtValidationResult Verify() => _signedValidator.Validate(_signedToken);

    [Benchmark(Description = "Sign + encrypt (ML-DSA-65 → X-Wing/A256GCM)")]
    public string SignThenEncrypt() => BuildEncrypted();

    [Benchmark(Description = "Decrypt + verify (X-Wing/A256GCM → ML-DSA-65)")]
    public PqJwtValidationResult DecryptAndVerify() => _encryptedValidator.Validate(_encryptedToken);

    private string BuildSigned() =>
        new PqJwtBuilder()
            .WithIssuer("https://bench.postquantum.jwt")
            .WithSubject("benchmark-subject")
            .WithAudience("benchmark-audience")
            .WithLifetime(TokenLifetime)
            .SignWith(_signingKey)
            .Build();

    private string BuildEncrypted() =>
        new PqJwtBuilder()
            .WithIssuer("https://bench.postquantum.jwt")
            .WithSubject("benchmark-subject")
            .WithAudience("benchmark-audience")
            .WithLifetime(TokenLifetime)
            .SignWith(_signingKey)
            .EncryptFor(_decryptionKey.PublicKey)
            .Build();
}
