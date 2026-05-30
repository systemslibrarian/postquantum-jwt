# Known Gaps

A transparent, running list of what PostQuantum.Jwt does **not** yet do, what is
unverified, and where the sharp edges are. Honesty over polish: if something is
incomplete, it is listed here rather than glossed over. This file is part of the
contract with anyone evaluating the library.

Last reviewed for: `0.1.0-preview.1`.

## Cryptography

- **No external audit.** No third party has reviewed the design or
  implementation. Do not use in production.
- **X-Wing encapsulation is not KAT-validated (BCL limitation).** Seed-based key
  generation and the decapsulation + SHA3-256 combiner path **are** checked
  against the official `draft-connolly-cfrg-xwing-kem` known-answer vectors
  (`spec/test-vectors.json`) — all three vectors pass. The *encapsulation* path
  is **not** KAT-checked: the native `MLKem.Encapsulate` draws its own randomness
  and exposes no derandomized ("Encaps_derand") entry point, so the vectors'
  `eseed` cannot be injected. Encapsulation is covered by round-trip tests
  instead. If a derandomized ML-KEM API becomes available, add the encaps KAT.
- **No independent ML-KEM / ML-DSA KATs in this repo.** We rely on the .NET BCL
  (FIPS-validated) for these primitives and do not re-test them here. If your
  threat model needs in-repo KATs, they are not present yet.
- **Constant-time behavior is inherited, not guaranteed.** We make no
  side-channel claims beyond what the BCL and BouncyCastle provide.
- **One algorithm suite only.** Only ML-DSA-65, ML-KEM-768, and AES-256-GCM are
  supported. There is no algorithm agility (e.g. ML-DSA-44/87, ML-KEM-512/1024)
  in this preview.

## Tokens & protocol

- **Non-standard JOSE identifiers.** `alg`/`enc` values (`ML-DSA-65`, `X-Wing`,
  `A256GCM` over a nested JWT) are not IANA-registered. Tokens will **not**
  validate in standard JWT tooling, and the wire format may change before 1.0.
- **Replay protection is opt-in and only as strong as the cache you provide.**
  `IPqJwtReplayCache` + the bundled `InMemoryReplayCache` enforce single-use
  `jti` when configured, but the in-memory cache is single-process and does not
  survive a restart. Distributed deployments must back the hook with a shared
  store. With no cache configured, `jti` is carried but not enforced.
- **`kid` resolution is supported but does not fetch keys.**
  `SignatureKeyResolver` lets you select a verification key from the token's
  `kid` (key rotation); you still supply the keys — there is no JWKS endpoint or
  remote key discovery.
- **Single fixed algorithm suite (by design).** No algorithm agility — see
  [`docs/adr/0001-algorithm-agility.md`](docs/adr/0001-algorithm-agility.md).
- **Single recipient for encryption.** A token can be encrypted to exactly one
  X-Wing public key; multi-recipient JWE is not implemented.
- **No compression, no detached payloads, no JSON (non-compact) serialization.**

## API & lifecycle

- **Preview API.** Public types and method signatures may change without notice
  until 1.0.
- **No streaming / large-payload API.** Everything operates on in-memory
  `string` / `byte[]`.
- **No DI / `IServiceCollection` integration, no ASP.NET Core authentication
  handler.** You wire the builder/validator in yourself.

## Tooling & environment

- **Native PQC requires OpenSSL 3.5+ (Linux) or a recent Windows.** Where
  ML-KEM / ML-DSA are unavailable, operations fail closed and the corresponding
  tests skip themselves with a stated reason.
- **CI does not yet guarantee a post-quantum-capable runner.** The GitHub Actions
  CI builds and tests on `ubuntu-latest`; if that runner's OpenSSL predates 3.5,
  the post-quantum tests (including the X-Wing KATs) **skip** rather than run.
  Until the pipeline pins an OpenSSL 3.5+ environment, treat green CI as covering
  the non-PQC paths plus whatever the runner supports.
- **Packages are not author-signed.** The release workflow packs and (optionally)
  pushes to NuGet, which applies repository signing. There is no code-signing
  certificate, so packages are not cryptographically *author*-signed yet.

---

If you hit a gap not listed here, that itself is a gap — please open an issue so
it can be recorded honestly.

---

*To God be the glory — 1 Corinthians 10:31.*
