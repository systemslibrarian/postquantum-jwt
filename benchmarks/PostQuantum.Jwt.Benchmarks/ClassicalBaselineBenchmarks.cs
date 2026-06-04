using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace PostQuantum.Jwt.Benchmarks;

/// <summary>
/// Classical (pre-quantum) baseline: an ES256 (ECDSA P-256 / SHA-256) JWT issued
/// and validated with Microsoft's modern <see cref="JsonWebTokenHandler"/>. This
/// is the reference point for "what does post-quantum cost you?" — run it in the
/// same session as <see cref="TokenBenchmarks"/> and compare the summaries.
/// </summary>
/// <remarks>
/// <para>
/// ES256 is the comparator on purpose: like ML-DSA-65 it is an <i>asymmetric</i>
/// signature (so the comparison is apples-to-apples, unlike HMAC/HS256), it is
/// the most widely deployed asymmetric JWT algorithm, and its signature is tiny
/// (~64 bytes vs. ML-DSA-65's 3,309). That size gap — not the CPU gap — is the
/// headline post-quantum cost; see <see cref="TokenSizeReport"/>.
/// </para>
/// <para>
/// The handler is the modern <see cref="JsonWebTokenHandler"/>, not the legacy
/// <c>JwtSecurityTokenHandler</c> from <c>System.IdentityModel.Tokens.Jwt</c>:
/// benchmarking against the faster, currently-recommended classical path keeps
/// the comparison honest rather than racing this library against a deprecated one.
/// </para>
/// </remarks>
[MemoryDiagnoser]
public class ClassicalBaselineBenchmarks
{
    private const string Issuer = "https://bench.postquantum.jwt";
    private const string Audience = "benchmark-audience";
    private static readonly TimeSpan TokenLifetime = TimeSpan.FromDays(365);

    private ECDsa _ecdsa = null!;
    private ECDsaSecurityKey _key = null!;
    private SigningCredentials _signingCredentials = null!;
    private JsonWebTokenHandler _handler = null!;
    private TokenValidationParameters _validationParameters = null!;
    private string _token = null!;

    [GlobalSetup]
    public void Setup()
    {
        _ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _key = new ECDsaSecurityKey(_ecdsa);
        _signingCredentials = new SigningCredentials(_key, SecurityAlgorithms.EcdsaSha256);
        _handler = new JsonWebTokenHandler();
        _validationParameters = new TokenValidationParameters
        {
            ValidIssuer = Issuer,
            ValidAudience = Audience,
            IssuerSigningKey = _key,
            ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
        };

        _token = CreateToken();
    }

    [GlobalCleanup]
    public void Cleanup() => _ecdsa.Dispose();

    [Benchmark(Description = "Classical sign (ES256)")]
    public string Sign() => CreateToken();

    [Benchmark(Description = "Classical verify (ES256)")]
    public async Task<bool> Verify()
    {
        var result = await _handler.ValidateTokenAsync(_token, _validationParameters);
        return result.IsValid;
    }

    private string CreateToken() => _handler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = Issuer,
        Audience = Audience,
        Expires = DateTime.UtcNow.Add(TokenLifetime),
        Claims = new Dictionary<string, object> { ["sub"] = "benchmark-subject" },
        SigningCredentials = _signingCredentials,
    });
}
