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
            throw new PqJwtValidationException(
                PqJwtFailureReason.MalformedJson, "Token header is not valid JSON.", ex);
        }

        if (node is not JsonObject obj)
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.InvalidHeader, "Token header is not a JSON object.");
        }

        var alg = AsString(obj["alg"]);
        if (string.IsNullOrEmpty(alg))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.InvalidHeader, "Token header is missing the 'alg' field.");
        }

        return new JoseHeader
        {
            Algorithm = alg,
            Encryption = AsString(obj["enc"]),
            Type = AsString(obj["typ"]),
            ContentType = AsString(obj["cty"]),
            KeyId = AsString(obj["kid"]),
        };
    }

    // Reads a header field as a string ONLY when it is a JSON string. A field that
    // is present but a number, array, object, or bool is treated as absent (null)
    // rather than throwing — an explicit (string?)node cast would raise
    // InvalidOperationException for those, which escapes the validator's fail-closed
    // catch filter. Returning null keeps every path fail-closed: a non-string 'alg'
    // becomes "missing alg", a non-string 'enc'/'cty' fails the algorithm/header
    // checks, and a non-string 'kid' resolves to no key.
    private static string? AsString(JsonNode? node) =>
        node is JsonValue value && value.TryGetValue<string>(out var s) ? s : null;
}
