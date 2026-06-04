using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;

namespace PostQuantum.Jwt.Benchmarks;

/// <summary>
/// "Time to first verified token" — the cold-start number that matters most for
/// serverless hosts (Azure Functions, AWS Lambda), where total throughput is
/// often irrelevant but the latency of the very first request is not.
/// </summary>
/// <remarks>
/// <para>
/// Uses <see cref="RunStrategy.ColdStart"/> with one invocation per launch and
/// many launches, so each measurement is taken in a <b>fresh process</b> that
/// has paid the first-call costs the warm benchmarks deliberately exclude: JIT
/// of the hot path and one-time native ML-DSA initialisation in the BCL.
/// </para>
/// <para>
/// Deliberately no <c>[GlobalSetup]</c> that touches crypto — key generation,
/// signing, and verification all happen inside the measured method on purpose.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.ColdStart, launchCount: 20, warmupCount: 0, iterationCount: 1, invocationCount: 1)]
public class ColdStartBenchmarks
{
    [Benchmark(Description = "Cold start: generate key → sign → verify (fresh process)")]
    public PqJwtValidationResult TimeToFirstVerifiedToken()
    {
        using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        using var verificationKey = MLDsa.ImportMLDsaPublicKey(
            MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());

        var token = new PqJwtBuilder()
            .WithIssuer("https://bench.postquantum.jwt")
            .WithSubject("benchmark-subject")
            .WithLifetime(TimeSpan.FromHours(1))
            .SignWith(signingKey)
            .Build();

        var validator = new PqJwtValidator(new PqJwtValidationParameters
        {
            SignatureVerificationKey = verificationKey,
        });

        return validator.Validate(token);
    }
}
