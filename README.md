# PostQuantum.Jwt

A post-quantum **hybrid** JWT library for .NET 10.

PostQuantum.Jwt issues and validates JSON Web Tokens whose security rests on a
**hybrid** of classical and post-quantum cryptography — so a token stays secure
as long as *either* the classical *or* the post-quantum half holds. Signatures
use **ML-DSA-65** (FIPS 204). Optional encryption uses **X-Wing**
(X25519 + ML-KEM-768) key agreement with **AES-256-GCM**.

The post-quantum primitives come from the **native .NET BCL**
(`System.Security.Cryptography.MLKem`, `MLDsa`). The only third-party dependency
is **BouncyCastle**, used solely for X25519 — the one piece the BCL does not yet
provide. See [Security posture](#security-posture) for the honest details.

> **Status: `0.1.0-preview.1` — preview software. Not for production use.**
> The API will change. The cryptographic construction has **not** been
> independently audited. Read [`KNOWN-GAPS.md`](KNOWN-GAPS.md) before relying on
> anything here.

---

## Why hybrid?

A cryptographically relevant quantum computer would break the elliptic-curve
math behind today's JWT signatures (EdDSA, ECDSA, RSA). Pure post-quantum
schemes are new and comparatively under-attacked. A **hybrid** scheme hedges
both risks at once:

- **Signatures — ML-DSA-65.** A NIST-standardized lattice signature
  (FIPS 204, security category 3).
- **Key agreement — X-Wing.** The IETF hybrid KEM combining the battle-tested
  **X25519** with **ML-KEM-768** (FIPS 203), bound together by a SHA3-256
  combiner. An attacker must break *both* to recover the key.

---

## Install

```bash
dotnet add package PostQuantum.Jwt --version 0.1.0-preview.1
```

**Runtime requirement:** the native ML-KEM / ML-DSA primitives require an
OpenSSL build that exposes them — **OpenSSL 3.5 or later** on Linux, or a
recent Windows. PostQuantum.Jwt fails closed with a clear error where they are
unavailable rather than silently falling back to weaker crypto.

---

## Usage

### Sign and validate a token (ML-DSA-65)

```csharp
using System.Security.Cryptography;
using PostQuantum.Jwt;

// Issuer holds the ML-DSA private key; verifiers hold the public key.
using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

string token = new PqJwtBuilder()
    .WithIssuer("https://issuer.example")
    .WithSubject("user-123")
    .WithAudience("https://api.example")
    .WithLifetime(TimeSpan.FromMinutes(30))
    .WithClaim("role", "admin")
    .SignWith(signingKey)
    .Build();

// Validation is fail-closed: anything wrong throws PqJwtValidationException.
using var verificationKey = MLDsa.ImportMLDsaPublicKey(
    MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());

var validator = new PqJwtValidator(new PqJwtValidationParameters
{
    SignatureVerificationKey = verificationKey,
    ValidIssuer   = "https://issuer.example",
    ValidAudience = "https://api.example",
});

PqJwtValidationResult result = validator.Validate(token);
Console.WriteLine(result.Subject);            // user-123
Console.WriteLine(result.GetString("role"));  // admin
```

### Sign *and* encrypt a token (X-Wing + AES-256-GCM)

When the payload is confidential, hand the builder a recipient's X-Wing public
key. The token is signed first, then encrypted ("sign-then-encrypt").

```csharp
using PostQuantum.Jwt.Cryptography;

// Recipient generates a key pair and publishes the public half.
using var recipient = XWingPrivateKey.Generate();
byte[] recipientPublic = recipient.PublicKey.Export();   // share this

string token = new PqJwtBuilder()
    .WithSubject("confidential-subject")
    .WithLifetime(TimeSpan.FromMinutes(5))
    .SignWith(signingKey)
    .EncryptFor(XWingPublicKey.Import(recipientPublic))
    .Build();

var validator = new PqJwtValidator(new PqJwtValidationParameters
{
    SignatureVerificationKey = verificationKey,
    DecryptionKey            = recipient,   // required for encrypted tokens
});

PqJwtValidationResult result = validator.Validate(token);
Console.WriteLine(result.WasEncrypted);  // True
```

### Key rotation (`kid`) and replay protection (`jti`)

Tag a signature with a key id and resolve it at validation time, and reject
replayed tokens with a `jti` cache:

```csharp
string token = new PqJwtBuilder()
    .WithKeyId("signing-key-2026")
    .WithJwtId(Guid.NewGuid().ToString("N"))
    .WithLifetime(TimeSpan.FromMinutes(5))
    .SignWith(signingKey)
    .Build();

var validator = new PqJwtValidator(new PqJwtValidationParameters
{
    // Pick a verification key from the token's kid (key rotation).
    SignatureKeyResolver = kid => keyRing.TryGetValue(kid, out var k) ? k : null,
    // Reject any jti seen before. InMemoryReplayCache is single-process;
    // implement IPqJwtReplayCache over a shared store for multi-node setups.
    ReplayCache = new InMemoryReplayCache(),
});
```

An unknown `kid`, a missing `jti`, or a replayed `jti` all fail closed.

---

## Token format

PostQuantum.Jwt uses JOSE-style compact serialization:

| Form      | Segments | Header `alg` / `enc`              |
|-----------|----------|-----------------------------------|
| Signed    | 3        | `ML-DSA-65`                       |
| Encrypted | 5        | `X-Wing` / `A256GCM` (nested JWT) |

These algorithm identifiers are **not** registered with IANA — see
[Security posture](#security-posture).

---

## Security posture

We aim to be honest about exactly what this library does and does not give you.

**What you get**

- **Hybrid by construction.** Encryption stays secure unless *both* X25519 and
  ML-KEM-768 fall; signatures rest on ML-DSA-65.
- **Native post-quantum primitives.** ML-KEM-768 and ML-DSA-65 are the .NET
  BCL implementations, not a re-implementation.
- **Fail-closed validation.** Bad signature, tampered ciphertext, expired or
  not-yet-valid token, wrong issuer/audience, missing `exp` — all throw. There
  is no "alg: none", no unsigned path, and no silent downgrade.
- **Strict, small-surface defaults.** Expiration is required, clock skew is a
  modest 60s, and only the exact post-quantum algorithms are accepted.

**What you must know**

- **One dependency — BouncyCastle — and why.** The .NET BCL does not ship
  X25519, the classical half of X-Wing. Rather than hand-roll elliptic-curve
  code, we use BouncyCastle's vetted X25519 (and its SHA3-256 for the X-Wing
  combiner). ML-KEM-768 and ML-DSA-65 remain on the native BCL. This trade-off
  is deliberate: we will not roll our own curve arithmetic.
- **Not audited.** No third party has reviewed this construction. X-Wing key
  generation and the decapsulation/combiner path **are** validated against the
  official IETF known-answer vectors; the encapsulation path is not (the native
  ML-KEM API is randomized). See [`KNOWN-GAPS.md`](KNOWN-GAPS.md).
- **Non-standard identifiers.** The `alg`/`enc` values describe a scheme the
  IANA JOSE registry does not cover, so these tokens are intentionally **not**
  interoperable with generic JWT tooling.
- **Preview.** Treat the API and wire format as unstable until 1.0.

Full detail lives in [`SECURITY.md`](SECURITY.md) and
[`KNOWN-GAPS.md`](KNOWN-GAPS.md). To report a vulnerability, see `SECURITY.md`.

---

## Building from source

```bash
dotnet build
dotnet test
```

Tests that exercise the native post-quantum primitives **skip themselves** (with
a clear reason) on hosts that lack ML-KEM / ML-DSA support, and run fully where
OpenSSL 3.5+ is present.

---

## License

[MIT](LICENSE).

---

*To God be the glory — 1 Corinthians 10:31.*
