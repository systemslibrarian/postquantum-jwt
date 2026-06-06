using System.Collections.Concurrent;
using System.Diagnostics.Metrics;

namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.OrdersApi;

/// <summary>
/// DEMO-ONLY metrics snapshot collector that subscribes to the
/// <c>pqjwt.validations</c> counter on the <c>PostQuantum.Jwt</c> meter
/// and aggregates counts by outcome/reason so the browser-driven landing
/// page can render the bounded-cardinality observability contract live —
/// proving the counter is real, the reason tags stay closed, and no
/// token or key material ever lands in a tag value.
/// </summary>
/// <remarks>
/// Gated by <c>EXPOSE_FAILURE_REASON</c> in <c>Program.cs</c>. Production
/// deployments do not register this collector; their snapshot endpoint
/// is therefore absent and there is no demo-side observation channel to
/// inspect. Library consumers wire their own OpenTelemetry exporter or
/// <see cref="MeterListener"/> as they would for any
/// <see cref="System.Diagnostics.Metrics"/> instrument.
/// </remarks>
public sealed class MetricsSnapshotCollector : IDisposable
{
    private readonly MeterListener _listener;
    private readonly ConcurrentDictionary<(string Outcome, string? Reason), long> _counts = new();

    public MetricsSnapshotCollector()
    {
        _listener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == "PostQuantum.Jwt" &&
                    instrument.Name == "pqjwt.validations")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            },
        };
        _listener.SetMeasurementEventCallback<long>(OnMeasurement);
        _listener.Start();
    }

    private void OnMeasurement(
        Instrument instrument,
        long value,
        ReadOnlySpan<KeyValuePair<string, object?>> tags,
        object? state)
    {
        string outcome = "unknown";
        string? reason = null;
        foreach (var tag in tags)
        {
            if (tag.Key == "outcome")
            {
                outcome = tag.Value?.ToString() ?? "unknown";
            }
            else if (tag.Key == "reason")
            {
                reason = tag.Value?.ToString();
            }
        }

        _counts.AddOrUpdate(
            (outcome, reason),
            value,
            (_, existing) => existing + value);
    }

    /// <summary>
    /// Returns a flat snapshot of counts. Keys are <c>"outcome"</c> for the
    /// untagged success path and <c>"outcome.reason"</c> for failures. The
    /// reason vocabulary is the library's closed taxonomy
    /// (<c>signature_mismatch</c>, <c>audience_mismatch</c>, <c>expired</c>,
    /// <c>replay_detected</c>, <c>unknown_kid</c>, <c>decryption_failed</c>,
    /// etc.); a reason name not in this vocabulary in the snapshot would be
    /// a library-side bug, not a demo bug.
    /// </summary>
    public IReadOnlyDictionary<string, long> Snapshot()
    {
        var result = new Dictionary<string, long>();
        foreach (var entry in _counts)
        {
            var (outcome, reason) = entry.Key;
            var key = reason is null ? outcome : $"{outcome}.{reason}";
            result[key] = entry.Value;
        }
        return result;
    }

    public void Dispose() => _listener.Dispose();
}
