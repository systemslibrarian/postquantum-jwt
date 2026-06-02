using System.Diagnostics.Metrics;
using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Verifies the <c>pqjwt.validations</c> observability counter: that success and
/// failure are counted at the right boundary with the right, non-sensitive tags,
/// and that the typed-reason → metric-tag mapping is total (no defined reason
/// silently falls through to "other"). Together with
/// <see cref="PqJwtFailureReasonTests"/> this is what lets us trust the dashboard:
/// the reason is a compiler-checked enum, and its tag is locked by a test.
/// </summary>
public sealed class PqJwtMetricsTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    private sealed record Measurement(string? Outcome, string? Reason);

    // Captures pqjwt.validations measurements emitted while the listener is alive.
    private static List<Measurement> CaptureWhile(Action body)
    {
        var captured = new List<Measurement>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (inst, l) =>
            {
                if (inst.Meter.Name == "PostQuantum.Jwt" && inst.Name == "pqjwt.validations")
                {
                    l.EnableMeasurementEvents(inst);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((_, _, tags, _) =>
        {
            string? outcome = null, reason = null;
            foreach (var tag in tags)
            {
                if (tag.Key == "outcome") outcome = tag.Value as string;
                else if (tag.Key == "reason") reason = tag.Value as string;
            }

            lock (captured)
            {
                captured.Add(new Measurement(outcome, reason));
            }
        });
        listener.Start();
        body();
        // Stop listening before returning so later tests' measurements don't land here.
        listener.Dispose();
        lock (captured)
        {
            return [.. captured];
        }
    }

    [PqcFact]
    public void Successful_validation_increments_outcome_success()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        var token = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(signing).Build();
        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = verify },
            new FixedTimeProvider(Now));

        var measurements = CaptureWhile(() => validator.Validate(token));

        Assert.Contains(measurements, m => m is { Outcome: "success", Reason: null });
    }

    [PqcFact]
    public void Rejected_validation_increments_outcome_failure_with_reason_tag()
    {
        using var signing = TestKeys.NewSigningKey();
        using var verify = TestKeys.PublicKeyOf(signing);
        using var attacker = TestKeys.NewSigningKey();
        var forged = new PqJwtBuilder(new FixedTimeProvider(Now))
            .WithLifetime(TimeSpan.FromMinutes(10)).SignWith(attacker).Build();
        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureVerificationKey = verify },
            new FixedTimeProvider(Now));

        var measurements = CaptureWhile(() =>
            Assert.Throws<PqJwtValidationException>(() => validator.Validate(forged)));

        Assert.Contains(measurements, m => m is { Outcome: "failure", Reason: "signature_mismatch" });
    }

    [Fact]
    public void Every_defined_reason_maps_to_a_distinct_non_default_tag()
    {
        var tags = new Dictionary<string, PqJwtFailureReason>(StringComparer.Ordinal);
        foreach (var reason in Enum.GetValues<PqJwtFailureReason>())
        {
            var tag = PqJwtValidator.ReasonTag(reason);

            if (reason == PqJwtFailureReason.Unspecified)
            {
                Assert.Equal("other", tag);
                continue;
            }

            Assert.NotEqual("other", tag);
            Assert.False(tags.ContainsKey(tag),
                $"Reason tag '{tag}' is shared by {reason} and {(tags.TryGetValue(tag, out var other) ? other : default)}.");
            tags[tag] = reason;
        }
    }
}
