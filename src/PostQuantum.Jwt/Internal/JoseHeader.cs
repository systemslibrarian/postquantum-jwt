using System.Text.Json;
using System.Text.Json.Nodes;

namespace PostQuantum.Jwt.Internal;

/// <summary>
/// A parsed JOSE protected header. Only the fields PostQuantum.Jwt cares about
/// are surfaced; unknown members are ignored on read.
/// </summary>
internal sealed class JoseHeader
{
    internal required string Algorithm { get; init; }

    internal string? Encryption { get; init; }

    internal string? Type { get; init; }

    internal string? ContentType { get; init; }

    internal string? KeyId { get; init; }

    internal static JoseHeader Parse(string json)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new PqJwtValidationException("Token header is not valid JSON.", ex);
        }

        if (node is not JsonObject obj)
        {
            throw new PqJwtValidationException("Token header is not a JSON object.");
        }

        var alg = (string?)obj["alg"];
        if (string.IsNullOrEmpty(alg))
        {
            throw new PqJwtValidationException("Token header is missing the 'alg' field.");
        }

        return new JoseHeader
        {
            Algorithm = alg,
            Encryption = (string?)obj["enc"],
            Type = (string?)obj["typ"],
            ContentType = (string?)obj["cty"],
            KeyId = (string?)obj["kid"],
        };
    }
}
