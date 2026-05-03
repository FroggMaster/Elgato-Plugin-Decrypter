namespace ElgatoDecrypter;

internal static class Constants
{
    // PCG PRNG parameters
    // PcgMult and PcgInc are standard PCG-64 algorithm constants and are
    // extremely unlikely to change between StreamDeck releases.
    public const ulong PcgMult       = 0x5851F42D4C957F2D;
    public const ulong PcgInc        = 0x14057B7EF767814F;

    /// <summary>
    /// Known PCG seed value as of the last verified StreamDeck build.
    /// Used only as a fallback in the legacy extraction path.
    /// The structural extraction path reads whatever seed value is present 
    /// in the binary, so it remains correct even after Elgato ships a new 
    /// build with a different seed.
    /// </summary>
    public const ulong PcgSeed       = 0xEED06C38416BF9F1;
    public const ulong XorInitConst  = 0x1A08EE1184BA6D32;

    // ELGATO archive magic values
    public static readonly byte[] MagicElgato = "ELGATO"u8.ToArray();
    public const uint MagicInfo = 0x4F464E49; // INFO
    public const uint MagicMeta = 0x4154454D; // META
    public const uint MagicData = 0x41544144; // DATA

    // Default StreamDeck.exe path
    public const string DefaultBinaryPath =
        @"C:\Program Files\Elgato\StreamDeck\StreamDeck.exe";
}
