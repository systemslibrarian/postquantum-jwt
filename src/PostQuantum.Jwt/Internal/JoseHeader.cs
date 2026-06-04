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

        // JsonNode.Parse is lazy: JsonObject defers building its name→node dictionary
        // until the first indexer access, and only at that point detects duplicate
        // member names (RFC 8259 §4 declares duplicate JSON keys non-interoperable;
        // RFC 7515 §4 requires JOSE header parameter names to be unique). The
        // resulting ArgumentException is not a JsonException, so it slips past the
        // catch above — wrap it here to keep Validate fail-closed.
        string? alg, enc, typ, cty, kid;
        try
        {
            alg = AsString(obj["alg"]);
            enc = AsString(obj["enc"]);
            typ = AsString(obj["typ"]);
            cty = AsString(obj["cty"]);
            kid = AsString(obj["kid"]);
        }
        catch (ArgumentException ex)
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.MalformedJson,
                "Token header has duplicate JSON property names.", ex);
        }

        if (string.IsNullOrEmpty(alg))
        {
            throw new PqJwtValidationException(
                PqJwtFailureReason.InvalidHeader, "Token header is missing the 'alg' field.");
        }

        return new JoseHeader
        {
            Algorithm = alg,
            Encryption = enc,
            Type = typ,
            ContentType = cty,
            KeyId = kid,
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
