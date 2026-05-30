# Known Gaps

A transparent, running list of what PostQuantum.Jwt does **not** yet do, what is
unverified, and where the sharp edges are. Honesty over polish: if something is
incomplete, it is listed here rather than glossed over. This file is part of the
contract with anyone evaluating the library.

Last reviewed for: `0.2.0-preview.2`.

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
- **PQ coverage in CI is proven by the Windows lane only.** As of `0.2.0-preview.1`
  the Windows CI lane runs the full suite **with zero skipped tests** and the
  workflow fails the run if anything skips — so the post-quantum paths are
  proven to execute on every push. The Linux lane is portability-only: if
  `ubuntu-latest` ever lands without OpenSSL 3.5+, PQ tests will skip there
  silently. A future improvement is a containerised Linux lane that pins
  OpenSSL 3.5+ so PQ coverage is asserted on both operating systems.
- **Packages are not author-signed.** The release workflow packs and (with
  manual approval on the `nuget-publish` GitHub Environment) pushes to NuGet,
  which applies repository signing. There is no author code-signing certificate
  yet. As an interim transparency signal, every release emits a GitHub
  build-provenance attestation for the `.nupkg`; verify with
  `gh attestation verify <nupkg> --repo systemslibrarian/postquantum-jwt`.
- **SBOM is generated and attested, but not yet packed inside the `.nupkg`.**
  Starting with `0.2.0-preview.2` the release workflow emits a CycloneDX
  SBOM (`bom.json`) covering the project's dependency graph, includes it in
  `SHA256SUMS.txt`, and issues a separate GitHub build-provenance attestation
  for it. The SBOM travels with the GitHub release artifacts, not inside the
  `.nupkg` itself — consumers who need it should pull it from the workflow
  run rather than relying on package contents.

---

If you hit a gap not listed here, that itself is a gap — please open an issue so
it can be recorded honestly.

---

*To God be the glory — 1 Corinthians 10:31.*
