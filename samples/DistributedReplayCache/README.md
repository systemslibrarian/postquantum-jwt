# Distributed replay cache (multi-node `jti` defense)

`InMemoryReplayCache` (in the library) is single-process: a token replayed on a
different node isn't detected. For a clustered deployment you need a **shared**
store. This sample implements `IPqJwtReplayCache` two ways.

## The one rule that matters: atomicity

`IPqJwtReplayCache.TryRegister` must **record-and-test atomically**. A naive
get-then-set lets two nodes racing the same replayed token both see "absent" and
both accept it — defeating the whole point.

| Implementation | Atomic? | Use when |
| -------------- | ------- | -------- |
| `RedisReplayCache` | **Yes** — Redis `SET … NX PX` | Recommended. True set-if-absent at the server. |
| `DistributedCacheReplayCache` | No (residual race) | Portability across `IDistributedCache` providers, if you accept the small window. |

## Wiring it in

```csharp
// Program.cs — register a shared multiplexer once, then the cache.
builder.Services.AddSingleton<IConnectionMultiplexer>(
    _ => ConnectionMultiplexer.Connect("your-redis:6379"));
builder.Services.AddSingleton<IPqJwtReplayCache>(sp =>
    new RedisReplayCache(sp.GetRequiredService<IConnectionMultiplexer>()));

// …then pass it to the validator / AddPqJwtBearer:
options.ValidationParameters = new PqJwtValidationParameters
{
    SignatureVerificationKey = verificationKey,
    ReplayCache = sp.GetRequiredService<IPqJwtReplayCache>(),
    RequireReplayProtection = true,   // constructor throws if the cache is missing
};
```

The TTL is derived from the token's `exp`, so entries evict themselves once the
token can no longer validate anyway — the cache never grows unbounded.

---

*To God be the glory — 1 Corinthians 10:31.*
