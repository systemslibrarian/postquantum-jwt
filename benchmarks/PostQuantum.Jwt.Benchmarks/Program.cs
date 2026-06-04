using System.Security.Cryptography;
using BenchmarkDotNet.Running;
using PostQuantum.Jwt.Benchmarks;

// The post-quantum primitives come from the native .NET BCL and need OpenSSL
// 3.5+ on Linux. Without them every benchmark here would throw rather than
// measure anything — so refuse to run and say why, instead of emitting numbers
// that don't reflect the library. (Honesty over polish: a benchmark that can't
// run its crypto must not pretend it did.)
if (!MLDsa.IsSupported || !MLKem.IsSupported)
{
    Console.Error.WriteLine(
        "Skipping benchmarks: native ML-DSA / ML-KEM are unsupported on this host (needs OpenSSL 3.5+).");
    Console.Error.WriteLine(
        "In this dev container, prefix the run with conda's OpenSSL:");
    Console.Error.WriteLine(
        "  LD_LIBRARY_PATH=/opt/conda/lib dotnet run -c Release -- --filter '*'");
    return 1;
}

// `--sizes` prints the token-size report and exits; it is not a timing
// benchmark, so it lives outside the BenchmarkDotNet switcher.
if (args.Length > 0 && string.Equals(args[0], "--sizes", StringComparison.Ordinal))
{
    TokenSizeReport.Print(Console.Out);
    return 0;
}

BenchmarkSwitcher.FromAssembly(typeof(TokenBenchmarks).Assembly).Run(args);
return 0;
