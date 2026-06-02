using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Jwt.Tests;

public sealed class PqJwtHooksTests
{
    private static readonly DateTimeOffset Now = new(2026, 5, 30, 12, 0, 0, TimeSpan.Zero);

    [PqcFact]
    public void Kid_resolver_selects_the_matching_verification_key()
    {
        using var keyA = TestKeys.NewSigningKey();
        using var keyB = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);

        var token = new PqJwtBuilder(clock)
            .WithKeyId("key-b")
            .WithSubject("s")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(keyB)
            .Build();

        using var pubA = TestKeys.PublicKeyOf(keyA);
        using var pubB = TestKeys.PublicKeyOf(keyB);
        var validator = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureKeyResolver = kid => kid switch
                {
                    "key-a" => pubA,
                    "key-b" => pubB,
                    _ => null,
                },
            },
            clock);

        var result = validator.Validate(token);
        Assert.Equal("s", result.Subject);
    }

    [PqcFact]
    public void Unknown_kid_fails_closed()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithKeyId("unknown")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var validator = new PqJwtValidator(
            new PqJwtValidationParameters { SignatureKeyResolver = _ => null },
            clock);

        Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
    }

    [PqcFact]
    public void Replaying_a_token_is_rejected_on_the_second_use()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var cache = new InMemoryReplayCache(clock);
        var token = new PqJwtBuilder(clock)
            .WithJwtId("unique-1")
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var validator = Validator(signingKey, clock, cache);

        validator.Validate(token); // first use succeeds
        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Contains("replay", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PqcFact]
    public void Replay_protection_requires_a_jti()
    {
        using var signingKey = TestKeys.NewSigningKey();
        var clock = new FixedTimeProvider(Now);
        var token = new PqJwtBuilder(clock)
            .WithLifetime(TimeSpan.FromMinutes(5))
            .SignWith(signingKey)
            .Build();

        var validator = Validator(signingKey, clock, new InMemoryReplayCache(clock));

        var ex = Assert.Throws<PqJwtValidationException>(() => validator.Validate(token));
        Assert.Contains("jti", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // These two tests assert the construction-time contract for
    // RequireReplayProtection. The contract is independent of any PQ
    // primitive — the validator constructor only checks "have a key OR a
    // resolver" and "if RequireReplayProtection then ReplayCache". So we
    // satisfy the key/resolver check with a no-op SignatureKeyResolver
    // (never invoked — validation is never run, only construction is
    // exercised). This keeps the tests runnable on every platform,
    // including CI runners without native ML-DSA.
    [Fact]
    public void RequireReplayProtection_with_no_cache_throws_at_construction()
    {
        var ex = Assert.Throws<ArgumentException>(() => new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureKeyResolver = _ => null,
                RequireReplayProtection = true,
            }));

        Assert.Contains("RequireReplayProtection", ex.Message, StringComparison.Ordinal);
        Assert.Contains("ReplayCache", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RequireReplayProtection_with_a_cache_constructs_fine()
    {
        var clock = new FixedTimeProvider(Now);

        // Should not throw — fail-closed flag is satisfied by the supplied cache.
        _ = new PqJwtValidator(
            new PqJwtValidationParameters
            {
                SignatureKeyResolver = _ => null,
                RequireReplayProtection = true,
                ReplayCache = new InMemoryReplayCache(clock),
            },
            clock);
    }

    [Fact]
    public void In_memory_cache_detects_replay_then_allows_reuse_after_expiry()
    {
        var clock = new MutableTimeProvider(Now);
        var cache = new InMemoryReplayCache(clock);

        Assert.True(cache.TryRegister("jti-1", Now.AddMinutes(1)));  // first use
        Assert.False(cache.TryRegister("jti-1", Now.AddMinutes(1))); // still live → replay

        clock.Now = Now.AddMinutes(2); // the entry has now expired
        Assert.True(cache.TryRegister("jti-1", clock.Now.AddMinutes(1))); // reuse allowed
    }

    private static PqJwtValidator Validator(MLDsa signingKey, TimeProvider clock, IPqJwtReplayCache cache) =>
        new(
            new PqJwtValidationParameters
            {
                SignatureVerificationKey = TestKeys.PublicKeyOf(signingKey),
                ReplayCache = cache,
            },
            clock);
}
