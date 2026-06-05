using System.Diagnostics;
using System.Runtime;
using PostQuantum.Jwt.Internal;
using Xunit;
using Xunit.Abstractions;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Timing-distribution probe for ML-DSA-65 verification cost as a function of
/// the *contents* of the failing signature — the property a constant-time
/// verifier must hold. Two tampered tokens are constructed, both with a byte
/// flipped inside the c̃ region (the first 48 bytes of an ML-DSA-65 signature,
/// per FIPS 204 §8.2 algorithm 3 step 1). Both fail with
/// <see cref="PqJwtFailureReason.SignatureMismatch"/>; both run the full
/// matrix-vector verify (corrupting c̃ does not let the algorithm short-circuit).
/// The only difference is the bytes the underlying ML-DSA primitive sees.
/// The latency of those two paths should not be statistically distinguishable
/// — that's what "constant-time verify" means in the cryptographically
/// meaningful region of the signature.
/// <para>
/// Two non-probes this test deliberately avoids:
/// </para>
/// <list type="bullet">
/// <item><b>Valid vs tampered:</b> validators intentionally skip claim
/// validation after signature failure (signature-before-claims ordering); any
/// timing difference there is the documented short-circuit, not a side
/// channel.</item>
/// <item><b>Tampering byte 0 vs the last byte:</b> the last bytes of an
/// ML-DSA-65 signature encode the hint h, which FIPS 204 algorithm 3 rejects
/// with ⊥ before the expensive matrix-vector multiplication if it decodes
/// improperly. That early reject is conforming and is not a useful oracle
/// (it tells the attacker nothing about how to forge), so we keep both
/// tamper positions inside c̃ where the full verify must run.</item>
/// </list>
/// <para>
/// This is <b>not</b> a formal constant-time proof — the .NET runtime, GC,
/// JIT tier-up, branch prediction, and OS scheduling all inject noise that
/// makes a wall-clock test inherently flaky. The check below mitigates noise
/// with long warmup, GC suppression around each sample, and a Welch's t-test
/// on the means; it raises a <b>strong-evidence</b> bar (|t| greater than a
/// generous threshold) before failing. A failure means the difference is
/// unlikely to be runtime jitter alone; it does not, on its own, prove a
/// timing oracle. A pass means no statistically detectable leak at this
/// scale, not a constant-time guarantee — that is honestly documented in
/// <c>KNOWN-GAPS.md</c>.
/// </para>
/// <para>
/// Opt-in via <c>dotnet test --filter Category=Timing</c>. The
/// <c>[Trait("Category", "Timing")]</c> annotation keeps it out of the default
/// suite, because the test reads physical time and a CI worker under load
/// will produce noisy samples.
/// </para>
/// </summary>
public sealed class ConstantTimeVerifyTests(ITestOutputHelper output)
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    [Trait("Category", "Timing")]
    [PqcFact]
    public void ML_DSA_verify_latency_inside_c_tilde_does_not_depend_on_byte_position()
    {
        const int warmup = 200;
        const int samples = 1500;
        // Welch's t-statistic threshold. |t| > 6 is vanishingly improbable
        // under the null hypothesis of equal means; chosen generously to
        // absorb runtime noise (a real timing oracle inside c̃ verify would
        // dwarf this).
        const double tThreshold = 6.0;

        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithSubject("s")
            .WithLifetime(TimeSpan.FromMinutes(30))
            .SignWith(signingKey)
            .Build();

        // Both positions are well inside the 48-byte c̃ region of an ML-DSA-65
        // signature, so the verifier cannot short-circuit on either path.
        var tamperedNearStart = TamperAt(token, position: 5);
        var tamperedNearEnd = TamperAt(token, position: 40);

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey) },
            clock);

        // Sanity: both tampered tokens fail with the same reason — proving
        // they take the same code path through the validator and any
        // statistical difference is coming from the verifier internals.
        Assert.Equal(PqJwtFailureReason.SignatureMismatch,
            Assert.Throws<PqJwtValidationException>(() => validator.Validate(tamperedNearStart)).Reason);
        Assert.Equal(PqJwtFailureReason.SignatureMismatch,
            Assert.Throws<PqJwtValidationException>(() => validator.Validate(tamperedNearEnd)).Reason);

        // Warmup: JIT tier-up and key-import caches stabilize.
        for (var i = 0; i < warmup; i++)
        {
            TimeFailure(validator, tamperedNearStart);
            TimeFailure(validator, tamperedNearEnd);
        }

        var startSamples = new double[samples];
        var endSamples = new double[samples];

        // Interleave so secular drift (thermal throttling, a background task
        // starting up halfway through) hits both distributions equally.
        for (var i = 0; i < samples; i++)
        {
            startSamples[i] = TimeFailure(validator, tamperedNearStart);
            endSamples[i] = TimeFailure(validator, tamperedNearEnd);
        }

        var (meanS, varS) = MeanVar(startSamples);
        var (meanE, varE) = MeanVar(endSamples);

        // Welch's t = |μ1 - μ2| / sqrt(s1² / n + s2² / n).
        var t = Math.Abs(meanS - meanE) / Math.Sqrt(varS / samples + varE / samples);

        output.WriteLine($"tampered@c̃[5]  mean={meanS:F3} µs  var={varS:F3}");
        output.WriteLine($"tampered@c̃[40] mean={meanE:F3} µs  var={varE:F3}");
        output.WriteLine($"|Welch t| = {t:F2}  (threshold {tThreshold})");

        Assert.True(
            t < tThreshold,
            $"Welch's t = {t:F2} exceeds {tThreshold}: ML-DSA verify latency depends on the "
            + $"byte position of a c̃ tamper (c̃[5] {meanS:F2} µs vs c̃[40] {meanE:F2} µs). "
            + "The full-verify path must be data-independent inside c̃ for the constant-time property to hold.");
    }

    private static double TimeFailure(PqJwtValidator validator, string token)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var noGc = GC.TryStartNoGCRegion(64 * 1024);

        var start = Stopwatch.GetTimestamp();
        try { _ = validator.Validate(token); }
        catch (PqJwtValidationException) { /* expected — measure the failure path */ }
        var elapsed = Stopwatch.GetElapsedTime(start);

        if (noGc && GCSettings.LatencyMode == GCLatencyMode.NoGCRegion)
        {
            GC.EndNoGCRegion();
        }

        return elapsed.TotalMicroseconds;
    }

    private static (double mean, double variance) MeanVar(double[] xs)
    {
        var mean = xs.Average();
        var variance = xs.Sum(x => (x - mean) * (x - mean)) / (xs.Length - 1);
        return (mean, variance);
    }

    private static string TamperAt(string token, int position)
    {
        // Flip one BYTE of the decoded signature, then re-encode. Tampering at
        // the character level of the base64url string would let
        // Base64Url.Decode short-circuit when the flipped char lands on slack
        // bits (canonical-encoding round-trip check rejects before the crypto
        // runs) — which would mean we'd be probing the parser's branch cost,
        // not ML-DSA's verify cost. Working at decoded-byte granularity puts
        // both tampered tokens through the canonical-encoding check
        // identically; only the bytes ML-DSA verifies differ.
        var parts = token.Split('.');
        var sigBytes = Base64Url.Decode(parts[2]);
        var idx = position < 0 ? sigBytes.Length + position : position;
        sigBytes[idx] ^= 0x01;
        parts[2] = Base64Url.Encode(sigBytes);
        return string.Join('.', parts);
    }
}
