using System.Security.Cryptography;
using PostQuantum.Jwt;

namespace PostQuantum.Jwt.Samples.ProductionDeploymentDemo.IssuerApi;

/// <summary>
/// Small in-memory signing-key ring for the deployment demo.
/// </summary>
/// <remarks>
/// This intentionally models the operational lifecycle without pretending to be a
/// production key store. A real issuer would load keys from a vault, HSM, sealed
/// secret, or another controlled key-management system.
/// </remarks>
public sealed class SigningKeyRing : IDisposable
{
    private readonly object _gate = new();
    private SigningKeyRecord _active = SigningKeyRecord.Generate("pqjwt-active");
    private SigningKeyRecord? _previous;
    private int _generation = 1;
    private bool _disposed;

    public SigningKeySnapshot Snapshot()
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return new SigningKeySnapshot(_active, _previous);
        }
    }

    public SigningKeyRecord Active
    {
        get
        {
            lock (_gate)
            {
                ThrowIfDisposed();
                return _active;
            }
        }
    }

    public IReadOnlyList<PublishedSigningKey> GetPublishedKeys()
    {
        lock (_gate)
        {
            ThrowIfDisposed();

            var keys = new List<PublishedSigningKey>
            {
                _active.ToPublished("active")
            };

            if (_previous is not null)
            {
                keys.Add(_previous.ToPublished("previous"));
            }

            return keys;
        }
    }

    public SigningKeyRotationResult Rotate()
    {
        lock (_gate)
        {
            ThrowIfDisposed();

            _previous?.Dispose();
            _previous = _active;

            _generation++;
            _active = SigningKeyRecord.Generate($"pqjwt-active-{_generation:000}");

            return new SigningKeyRotationResult(
                ActiveKid: _active.Kid,
                PreviousKid: _previous.Kid,
                PublishedKeyCount: GetPublishedKeysUnderLock().Count);
        }
    }

    public SigningKeyRetirementResult RetirePrevious()
    {
        lock (_gate)
        {
            ThrowIfDisposed();

            var retiredKid = _previous?.Kid;
            _previous?.Dispose();
            _previous = null;

            return new SigningKeyRetirementResult(
                RetiredKid: retiredKid,
                ActiveKid: _active.Kid,
                PublishedKeyCount: GetPublishedKeysUnderLock().Count);
        }
    }

    private IReadOnlyList<PublishedSigningKey> GetPublishedKeysUnderLock()
    {
        var keys = new List<PublishedSigningKey> { _active.ToPublished("active") };
        if (_previous is not null)
        {
            keys.Add(_previous.ToPublished("previous"));
        }

        return keys;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _active.Dispose();
            _previous?.Dispose();
            _disposed = true;
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

public sealed record SigningKeySnapshot(SigningKeyRecord Active, SigningKeyRecord? Previous);

public sealed record SigningKeyRotationResult(string ActiveKid, string PreviousKid, int PublishedKeyCount);

public sealed record SigningKeyRetirementResult(string? RetiredKid, string ActiveKid, int PublishedKeyCount);

public sealed record PublishedSigningKey(string Kid, string Status, string Alg, string Key);

public sealed class SigningKeyRecord : IDisposable
{
    private bool _disposed;

    private SigningKeyRecord(string kid, MLDsa key, byte[] publicKey)
    {
        Kid = kid;
        Key = key;
        PublicKey = publicKey;
    }

    public string Kid { get; }

    public MLDsa Key { get; }

    public byte[] PublicKey { get; }

    public static SigningKeyRecord Generate(string kid)
    {
        var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
        return new SigningKeyRecord(kid, key, key.ExportMLDsaPublicKey());
    }

    public PublishedSigningKey ToPublished(string status) =>
        new(Kid, status, PqJwtAlgorithms.MLDsa65, Convert.ToBase64String(PublicKey));

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Key.Dispose();
        CryptographicOperations.ZeroMemory(PublicKey);
        _disposed = true;
    }
}
