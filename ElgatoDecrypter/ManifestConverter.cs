using System.Text.Json;
using System.Text.Json.Nodes;

namespace ElgatoDecrypter;

/// <summary>
/// Output format selector for the plugin conversion pipeline.
/// </summary>
internal enum OutputFormat
{
    /// <summary>Standard Stream Deck output. No manifest transformation is applied.</summary>
    StreamDeck,

    /// <summary>
    /// Stream Dock output. Remaps and removes fields to make the manifest
    /// compatible with the MiraBox Stream Dock SDK.
    /// </summary>
    StreamDock,
}

/// <summary>
/// Converts a decrypted Stream Deck manifest.json into a format
/// compatible with the MiraBox Stream Dock SDK.
/// Reference: https://sdk.key123.vip/en/guide/manifest.html
/// </summary>
internal static class ManifestConverter
{
    // Field mapping tables

    /// <summary>
    /// Maps Stream Deck controller names to their Stream Dock equivalents.
    /// </summary>
    private static readonly Dictionary<string, string> ControllerMap =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["Keypad"]          = "Keypad",
            ["Encoder"]         = "Knob",
            ["TouchBar"]        = "SecondaryScreen",
            ["LCD"]             = "SecondaryScreen",
            ["SecondaryScreen"] = "SecondaryScreen",
            ["Knob"]            = "Knob",
            ["Information"]     = "Information",
            ["btn"]             = "btn",
        };

    /// <summary>
    /// Top-level manifest fields that are Stream Deck-specific
    /// and must be removed when converting to a Stream Dock manifest.
    /// </summary>
    private static readonly HashSet<string> StreamDeckOnlyRoot =
        new(StringComparer.OrdinalIgnoreCase)
        {
            //"$schema",      // Manifest schema URL
            "Marketplace",    // Elgato marketplace metadata
            "Files",          // Elgato file integrity hashes
            "SupportURL",     // Added in SD 6.9
            "Profiles",       // Window profiles, not supported in Stream Dock
            "DefaultWindowSize",
            "LinkApplications",
        };

    /// <summary>
    /// Manifest fields that are Stream Deck-specific and appear inside each action
    /// object. These must be removed when converting to a Stream Dock manifest.
    /// </summary>
    private static readonly HashSet<string> StreamDeckOnlyAction =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Encoder",
            "DisableAutomaticIdentifiers",
            "DisableAutomaticStates",
            "DisableCaching",
            "SupportedInKeyLogicActions",  // Added in SD 7.0
            "SupportURL",                  // Added in SD 6.9, appears inside each action object
        };

    /// <summary>
    /// State-level manifest fields that are Stream Deck-specific
    /// and must be removed when converting to a Stream Dock manifest.
    /// </summary>
    private static readonly HashSet<string> StreamDeckOnlyState =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "Name",             // Multi-action state label, not part of the Stream Dock spec
            "MultiActionImage", // Image shown in the multi-action view, not supported in Stream Dock
        };

    // Conversion logic

    /// <summary>
    /// Transforms a decrypted Stream Deck manifest.json payload into a
    /// Stream Dock-compatible manifest. Returns indented UTF-8 JSON bytes.
    /// </summary>
    public static byte[] ToStreamDock(byte[] manifestJson)
    {
        JsonNode root = JsonNode.Parse(manifestJson)
            ?? throw new InvalidDataException("manifest.json is not valid JSON");

        // Root-level field adjustments

        // Stream Dock uses SDK version 1
        root["SDKVersion"] = 1;

        // Set the minimum Stream Dock version required to run Node.js plugins
        if (root["Software"] is JsonObject sw)
            sw["MinimumVersion"] = "2.9";
        else
            root["Software"] = new JsonObject { ["MinimumVersion"] = "2.9" };

        // Remove top-level fields that are not supported by Stream Dock
        if (root is JsonObject rootObj)
            foreach (var field in StreamDeckOnlyRoot)
                rootObj.Remove(field);

        // Per-action adjustments
        if (root["Actions"] is JsonArray actions)
        {
            foreach (var actionNode in actions)
            {
                if (actionNode is not JsonObject action) continue;

                // Translate Stream Deck controller names to Stream Dock equivalents
                if (action["Controllers"] is JsonArray controllers)
                {
                    var mapped = controllers
                        .Select(c => c?.GetValue<string>())
                        .Where(c => c is not null)
                        .Select(c => ControllerMap.TryGetValue(c!, out var m) ? m : c!)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();

                    action["Controllers"] = new JsonArray(
                        mapped.Select(m => (JsonNode?)JsonValue.Create(m)).ToArray());
                }

                // Remove action fields that are not supported by Stream Dock
                foreach (var field in StreamDeckOnlyAction)
                    action.Remove(field);

                // Per-state adjustments
                if (action["States"] is JsonArray states)
                {
                    foreach (var stateNode in states)
                    {
                        if (stateNode is not JsonObject state) continue;

                        // Remove state fields that are not supported by Stream Dock
                        foreach (var field in StreamDeckOnlyState)
                            state.Remove(field);

                        // Stream Deck uses "middle" for vertical centering; Stream Dock expects "center"
                        if (state["TitleAlignment"]?.GetValue<string>() == "middle")
                            state["TitleAlignment"] = "center";
                    }
                }
            }
        }

        // Serialize the result
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };
        return JsonSerializer.SerializeToUtf8Bytes(root, opts);
    }
}
