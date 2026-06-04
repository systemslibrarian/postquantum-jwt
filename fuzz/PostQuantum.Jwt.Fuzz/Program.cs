using System.Security.Cryptography;
using System.Text;
using PostQuantum.Jwt;
using PostQuantum.Jwt.Cryptography;
using SharpFuzz;

// Coverage-guided fuzz target for PqJwtValidator.Validate (SharpFuzz + libFuzzer).
//
// The contract under test is the same two total properties the FsCheck suite
// (PqJwtFuzzTests) checks, but explored with coverage feedback rather than random
// generation:
//   1. Fail-closed totality — every input either validates or throws a documented
//      PqJwtException; ANY other escaping exception is a bug. We let it propagate
//      so libFuzzer records the crash + the reproducing input.
//   2. No spurious acceptance — no fuzzer input can be a genuinely signed token
//      (it can't forge an ML-DSA-65 signature for our random key), so an accepted
//      token is a bug; we throw to flag it.
//
// Build / instrument / run: see README.md in this directory.

if (!MLDsa.IsSupported || !MLKem.IsSupported)
{
    Console.Error.WriteLine(
        "Native ML-DSA / ML-KEM unavailable (need OpenSSL 3.5+); cannot fuzz. " +
        "On Linux, put a 3.5+ libcrypto on LD_LIBRARY_PATH first.");
    return 1;
}

// Keys are random per process — safe, because no fuzzer input can produce a valid
// signature against them. Lifetime checks off so we exercise structure and
// cryptography rather than the clock.
//
// Why these are local (not static field-initializers): SharpFuzz instruments
// every method in the target assembly, including ctors. Any instrumented code
// run *before* Fuzzer.LibFuzzer.Run maps libFuzzer's coverage shared memory
// hits a null trace-pointer and crashes with AccessViolationException. So the
// validator (an instrumented type) MUST be constructed inside the callback,
// after Run has wired up shared memory. The keys above use only BCL types
// (MLDsa, XWingPrivateKey lives in PostQuantum.Jwt.Cryptography which we keep
// out of the sharpfuzz prefix list) so they're safe to build at startup.
using var signingKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
using var verificationKey = MLDsa.ImportMLDsaPublicKey(
    MLDsaAlgorithm.MLDsa65, signingKey.ExportMLDsaPublicKey());
using var recipient = XWingPrivateKey.Generate();

PqJwtValidator? validator = null;

Fuzzer.LibFuzzer.Run(bytes =>
{
    validator ??= new PqJwtValidator(new PqJwtValidationParameters
    {
        SignatureVerificationKey = verificationKey,
        DecryptionKey = recipient,
        ValidateLifetime = false,
    });

    var token = Encoding.UTF8.GetString(bytes);
    if (token.Length == 0)
    {
        return; // documented ArgumentException guard on empty input — not in scope
    }

    try
    {
        validator.Validate(token);

        // Reached only if validation SUCCEEDED. Impossible without a valid
        // ML-DSA-65 signature over the token's own header.payload, which the
        // fuzzer cannot forge — so this is a genuine finding.
        throw new InvalidOperationException(
            "FUZZ FINDING: validator accepted a fuzzer-produced token.");
    }
    catch (PqJwtException)
    {
        // Fail-closed exactly as designed. Any OTHER exception type is not caught
        // here, so it propagates to libFuzzer as a crash with a reproducer.
    }
});

return 0;
