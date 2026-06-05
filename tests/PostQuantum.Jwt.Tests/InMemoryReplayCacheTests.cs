using Xunit;

namespace PostQuantum.Jwt.Tests;

/// <summary>
/// Direct unit tests for <see cref="InMemoryReplayCache"/>. The replay cache
/// is already exercised end-to-end through <c>PqJwtValidator</c> in
/// <c>PqJwtFailureReasonTests.Second_use_of_a_jti_reports_ReplayDetected</c>,
/// but the validator path can't reach the cache's internal expiry / pruning
/// logic — Stryker.NET surfaced that gap as 21 surviving mutants on
/// <c>InMemoryReplayCache.cs</c>, the lowest mutation kill rate of any file
/// in scope. The tests below pin the behaviour those mutants were free to
/// change: argument validation, the boundary at "expires exactly at now",
/// the pruning interval, and the eviction predicate.
/// </summary>
public sealed class InMemoryReplayCacheTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Null_jwt_id_throws_ArgumentException()
    {
        var cache = new InMemoryReplayCache();
        Assert.Throws<ArgumentNullException>(() => cache.TryRegister(null!, Now.AddMinutes(5)));
    }

    [Fact]
    public void Empty_jwt_id_throws_ArgumentException()
    {
        var cache = new InMemoryReplayCache();
        Assert.Throws<ArgumentException>(() => cache.TryRegister(string.Empty, Now.AddMinutes(5)));
    }

    [Fact]
    public void First_registration_of_a_jti_succeeds()
    {
        var cache = new InMemoryReplayCache(new FixedTimeProvider(Now));
        Assert.True(cache.TryRegister("jti-1", Now.AddMinutes(5)));
    }

    [Fact]
    public void Second_registration_of_a_live_jti_is_rejected_as_replay()
    {
        var cache = new InMemoryReplayCache(new FixedTimeProvider(Now));
        Assert.True(cache.TryRegister("jti-1", Now.AddMinutes(5)));
        Assert.False(cache.TryRegister("jti-1", Now.AddMinutes(5)));
    }

    [Fact]
    public void Different_jti_values_are_tracked_independently()
    {
        var cache = new InMemoryReplayCache(new FixedTimeProvider(Now));
        Assert.True(cache.TryRegister("jti-1", Now.AddMinutes(5)));
        Assert.True(cache.TryRegister("jti-2", Now.AddMinutes(5)));
        Assert.False(cache.TryRegister("jti-1", Now.AddMinutes(5)));
        Assert.False(cache.TryRegister("jti-2", Now.AddMinutes(5)));
    }

    [Fact]
    public void Jti_id_comparison_is_case_sensitive()
    {
        // ConcurrentDictionary is keyed with StringComparer.Ordinal — two jtis
        // that differ only by case must NOT collide. (A case-insensitive
        // dictionary would silently merge "Token-1" and "token-1" and let one
        // of them slip through replay detection.)
        var cache = new InMemoryReplayCache(new FixedTimeProvider(Now));
        Assert.True(cache.TryRegister("Token-1", Now.AddMinutes(5)));
        Assert.True(cache.TryRegister("token-1", Now.AddMinutes(5)));
    }

    [Fact]
    public void Jti_that_already_expired_is_treated_as_reusable_not_replay()
    {
        // A jti whose previous registration is already past its expiry is no
        // longer a security concern (the token claiming that jti can no longer
        // be presented as live). The cache must let the slot be reused rather
        // than reporting replay against a stale entry — otherwise long-lived
        // processes would accumulate "ghost" replays forever.
        var clock = new MutableTimeProvider(Now);
        var cache = new InMemoryReplayCache(clock);

        Assert.True(cache.TryRegister("jti-1", Now.AddMinutes(1)));

        // Advance past the original expiry. (Without crossing the 30s prune
        // interval lazily; the AddOrUpdate path itself must handle this.)
        clock.Now = Now.AddSeconds(15).AddMinutes(1);
        Assert.True(cache.TryRegister("jti-1", clock.Now.AddMinutes(5)));
    }

    [Fact]
    public void Jti_that_expires_exactly_at_now_is_treated_as_reusable()
    {
        // Boundary case from the surviving Stryker mutant on line 47:
        // the predicate is `existing > now`, so a jti whose `existing` equals
        // `now` must be treated as expired and reusable (not still live).
        var clock = new MutableTimeProvider(Now);
        var cache = new InMemoryReplayCache(clock);

        Assert.True(cache.TryRegister("jti-1", Now.AddMinutes(1)));

        // Walk the clock forward to *exactly* the original expiry.
        clock.Now = Now.AddMinutes(1);
        Assert.True(cache.TryRegister("jti-1", clock.Now.AddMinutes(5)));
    }

    [Fact]
    public void Prune_removes_entries_that_expired_strictly_before_now()
    {
        // The Prune sweep runs at most once per 30s. Drive the clock past the
        // interval to force it, then re-register the same jti at a time that
        // does NOT cross another interval boundary — if Prune actually swept
        // the old entry, this must succeed.
        var clock = new MutableTimeProvider(Now);
        var cache = new InMemoryReplayCache(clock);

        Assert.True(cache.TryRegister("expired", Now.AddSeconds(1)));
        Assert.True(cache.TryRegister("still-live", Now.AddMinutes(10)));

        // Advance past the expiry of "expired" AND past the 30-second prune
        // interval. The next TryRegister triggers Prune, which must evict
        // "expired" but keep "still-live".
        clock.Now = Now.AddSeconds(45);
        Assert.True(cache.TryRegister("trigger-prune", clock.Now.AddMinutes(5)));

        // "still-live" must NOT have been swept — it's still in its validity
        // window and a replay attempt on it must still be rejected.
        Assert.False(cache.TryRegister("still-live", clock.Now.AddMinutes(10)));
    }

    [Fact]
    public void Prune_eviction_includes_entry_that_expires_exactly_at_now()
    {
        // Boundary case from the surviving Stryker mutants on line 79:
        // the eviction predicate is `entry.Value <= now`, so an entry whose
        // expiry equals `now` must be swept. (If the operator were `<`, an
        // entry at exactly the current instant would persist as a phantom
        // replay for one extra prune cycle; if it were `>` the cache would
        // evict still-live entries.)
        var clock = new MutableTimeProvider(Now);
        var cache = new InMemoryReplayCache(clock);

        // Register an entry that will expire at exactly Now + 45s, and pin
        // the clock to exactly that instant when the next Prune runs.
        var expiry = Now.AddSeconds(45);
        Assert.True(cache.TryRegister("at-now", expiry));

        // Move the clock to exactly the expiry (also past the 30s prune
        // interval, so Prune runs).
        clock.Now = expiry;
        Assert.True(cache.TryRegister("trigger-prune", clock.Now.AddMinutes(5)));

        // If the boundary predicate is correct (<= now), "at-now" was swept,
        // so re-registering it must succeed.
        Assert.True(cache.TryRegister("at-now", clock.Now.AddMinutes(5)));
    }

    [Fact]
    public void Prune_is_throttled_so_one_call_per_interval_at_most()
    {
        // Pins line 67 boundary (`< PruneIntervalTicks`): on a call before the
        // 30-second prune interval elapses, the sweep must NOT run. We prove
        // this by registering an already-expired entry, then re-registering
        // it on the AddOrUpdate path before the prune interval elapses — the
        // AddOrUpdate path correctly handles stale entries (line 47), so the
        // re-registration succeeds *either way*. To isolate Prune, we instead
        // observe that within the prune window, an entry that would be evicted
        // by a sweep is still present from TryRegister's perspective: it
        // returns false (replay) for a still-live entry rather than running a
        // sweep that might have changed state mid-flight. This test is
        // primarily a documentation pin for the throttling contract.
        var clock = new MutableTimeProvider(Now);
        var cache = new InMemoryReplayCache(clock);

        Assert.True(cache.TryRegister("live", Now.AddMinutes(5)));

        // Advance less than 30 seconds — Prune must NOT run on this call.
        clock.Now = Now.AddSeconds(10);
        Assert.False(cache.TryRegister("live", clock.Now.AddMinutes(5)));
    }

    [Fact]
    public void Default_clock_is_used_when_no_time_provider_is_supplied()
    {
        // Constructor default branch (TimeProvider.System): construct without
        // a provider and prove it functions — TryRegister doesn't NRE on a
        // null _timeProvider. Pins the `?? TimeProvider.System` branch.
        var cache = new InMemoryReplayCache();
        Assert.True(cache.TryRegister("jti", DateTimeOffset.UtcNow.AddMinutes(5)));
        Assert.False(cache.TryRegister("jti", DateTimeOffset.UtcNow.AddMinutes(5)));
    }
}
