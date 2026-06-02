// FileBackedSigningKey
//
// The WebApiDemo's main Program.cs generates a NEW signing key on every startup
// and warns loudly that a real service must NOT do that. THIS file is the other
// half of that lesson: the smallest honest example of *persisting* an ML-DSA-65
// signing key across restarts, so issued tokens survive a redeploy.
//
// It demonstrates the real .NET 10 BCL key lifecycle:
//   • export the private key as PKCS#8  (MLDsa.ExportPkcs8PrivateKey)
//   • write it to disk once, with locked-down file permissions
//   • load it back on startup          (MLDsa.ImportPkcs8PrivateKey)
//   • derive + publish the public half  (ExportSubjectPublicKeyInfo)
//
// WHY PKCS#8 and not the raw seed/secret-key exports? PKCS#8 is the portable,
// standards-based container the rest of the .NET ecosystem understands, it
// round-trips cleanly, and it has an *encrypted* variant
// (ExportEncryptedPkcs8PrivateKey) you should prefer in production. The compact
// alternative is the 32-byte private seed (ExportMLDsaPrivateSeed /
// ImportMLDsaPrivateSeed) — smallest to store, but rawer.
//
// WHAT THIS IS STILL NOT: production key management. A real deployment stores
// the key in an HSM, Azure Key Vault, or at minimum an OS keystore — never a
// plaintext PKCS#8 file on the app's own disk. This class uses an encrypted
// PKCS#8 file with a passphrase as a deliberate middle ground: it shows the
// export/import mechanics honestly without pretending a file is a vault.
//
// To God be the glory - 1 Corinthians 10:31.

using System.Security.Cryptography;

namespace PostQuantum.Jwt.WebApiDemo;

/// <summary>
/// A signing key that is generated once, persisted to an encrypted PKCS#8 file,
/// and reloaded on every subsequent startup — so tokens issued before a restart
/// keep validating after it. Holds both the private signing key and the derived
/// public verification key for the life of the process.
/// </summary>
public sealed class FileBackedSigningKey : IDisposable
{
    private const string Kid = "demo-persistent-2026-01";

    /// <summary>The ML-DSA-65 private key used to sign tokens.</summary>
    public MLDsa SigningKey { get; }

    /// <summary>The matching public key, for verification and for the key directory.</summary>
    public MLDsa VerificationKey { get; }

    /// <summary>Raw public-key bytes, base64-encoded into the JWKS-equivalent directory.</summary>
    public byte[] PublicKeyBytes { get; }

    /// <summary>The key id this signer stamps into a token's <c>kid</c> header.</summary>
    public string KeyId => Kid;

    /// <summary>Whether the key was loaded from disk (true) or freshly generated (false).</summary>
    public bool LoadedFromDisk { get; }

    private FileBackedSigningKey(MLDsa signingKey, bool loadedFromDisk)
    {
        SigningKey = signingKey;
        LoadedFromDisk = loadedFromDisk;

        // The public half is always derived from the private key — never stored
        // separately, so the two cannot drift.
        PublicKeyBytes = signingKey.ExportMLDsaPublicKey();
        VerificationKey = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa65, PublicKeyBytes);
    }

    /// <summary>
    /// Loads the signing key from <paramref name="path"/> if it exists, otherwise
    /// generates a new one and persists it (encrypted) for next time.
    /// </summary>
    /// <param name="path">File path for the encrypted PKCS#8 key material.</param>
    /// <param name="passphrase">Passphrase protecting the PKCS#8 file. In a real
    /// service this comes from a secret store, NOT source or config.</param>
    public static FileBackedSigningKey LoadOrCreate(string path, string passphrase)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentException.ThrowIfNullOrEmpty(passphrase);

        // These ML-DSA export/import APIs are still marked experimental in .NET 10.
#pragma warning disable SYSLIB5006
        if (File.Exists(path))
        {
            byte[] encrypted = File.ReadAllBytes(path);
            // Reconstruct the exact same key from the encrypted PKCS#8 blob.
            var loaded = MLDsa.ImportEncryptedPkcs8PrivateKey(passphrase, encrypted);
            return new FileBackedSigningKey(loaded, loadedFromDisk: true);
        }

        // First run: generate, then persist encrypted so the NEXT start reuses it.
        var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

        // PBES2 with sensible-for-a-demo iteration count. Tune for your threat model.
        var pbe = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, iterationCount: 200_000);
        byte[] encryptedPkcs8 = key.ExportEncryptedPkcs8PrivateKey(passphrase, pbe);

        WriteLockedDown(path, encryptedPkcs8);
#pragma warning restore SYSLIB5006

        return new FileBackedSigningKey(key, loadedFromDisk: false);
    }

    // Write the key file with owner-only permissions where the OS supports it.
    private static void WriteLockedDown(string path, byte[] bytes)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        // Create the file with owner-only permissions ATOMICALLY (UnixCreateMode is
        // applied at open time), so the key bytes are never briefly world/group-
        // readable between the write and a later chmod — closing the TOCTOU window a
        // WriteAllBytes-then-SetUnixFileMode sequence would leave open. On Windows,
        // UnixCreateMode is ignored; rely on ACL inheritance from a protected
        // directory (or DPAPI in a real implementation).
        var options = new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite; // chmod 600
        }

        using var stream = new FileStream(path, options);
        stream.Write(bytes);
    }

    public void Dispose()
    {
        SigningKey.Dispose();
        VerificationKey.Dispose();
    }
}
