using ElgatoDecrypter;

// Parse command line arguments

string? inputPath   = null;
string? outputFile  = null;
string  binaryPath  = Constants.DefaultBinaryPath;
OutputFormat format = OutputFormat.StreamDeck;

for (int i = 0; i < args.Length; i++)
{
    if ((args[i] == "--binary" || args[i] == "-b") && i + 1 < args.Length)
        binaryPath = args[++i];
    else if ((args[i] == "--output" || args[i] == "-o") && i + 1 < args.Length)
        outputFile = args[++i];
    else if ((args[i] == "--format" || args[i] == "-f") && i + 1 < args.Length)
    {
        string fmt = args[++i];
        format = fmt.ToLowerInvariant() switch
        {
            "streamdeck" => OutputFormat.StreamDeck,
            "streamdock" => OutputFormat.StreamDock,
            _ => throw new ArgumentException(
                $"Unknown format '{fmt}'. Valid values: streamdeck, streamdock")
        };
    }
    else if (inputPath is null)
        inputPath = args[i];
}

if (inputPath is null)
{
    Cli.WriteLine("Usage: elgato-decrypter <input> [options]");
    Cli.WriteLine();
    Cli.WriteLine("  input              Path to encrypted manifest.json or .streamDeckPlugin file");    Cli.WriteLine("Options:");
    Cli.WriteLine("  --output, -o <path> Output file or directory");
    Cli.WriteLine("  --binary, -b <path> Path to StreamDeck.exe for key extraction");
    Cli.WriteLine("  --format, -f <fmt>  Output format: streamdeck (default) | streamdock");
    Cli.WriteLine();
    Cli.WriteLine("Examples:");
    Cli.WriteLine("  elgato-decrypter plugin.streamDeckPlugin");
    Cli.WriteLine("  elgato-decrypter plugin.streamDeckPlugin -o output.json");
    Cli.WriteLine("  elgato-decrypter plugin.streamDeckPlugin --format streamdock");
    return 1;
}

// Determine if input is a ZIP file

bool isZip = inputPath.EndsWith(".streamDeckPlugin", StringComparison.OrdinalIgnoreCase)
          || inputPath.EndsWith(".zip",              StringComparison.OrdinalIgnoreCase);

if (!isZip)
{
    if (!File.Exists(inputPath))
    {
        Cli.WriteLine($"[-] Error: File not found: {inputPath}");
        return 1;
    }

    // Check ZIP magic bytes (PK\x03\x04)
    byte[] magic4 = new byte[4];
    using (var fs = File.OpenRead(inputPath))
        _ = fs.Read(magic4, 0, 4);

    if (magic4[0] == 0x50 && magic4[1] == 0x4B && magic4[2] == 0x03 && magic4[3] == 0x04)
        isZip = true;
}

// Extract encryption keys from StreamDeck binary
// For ZIP files in StreamDock format without encrypted content, key extraction 
// can be skipped. For all other cases we extract keys upfront.

byte[]? vault2Key = null;
byte[]? vault3Key = null;

bool needsKeys = !isZip || format == OutputFormat.StreamDeck
    || Archive.ZipContainsEncryptedManifest(inputPath);

if (needsKeys)
{
    Cli.WriteLine($"[*] Extracting keys from: {binaryPath}");
    var extractor = new KeyExtractor(binaryPath);
    var keys = extractor.Extract();

    if (keys is null)
    {
        Cli.WriteLine("[-] Fatal: Could not extract keys from binary.");
        return 1;
    }

    var (v1Indices, v2Indices, v3Indices, xorMask, pcgSeed) = keys.Value;

    Cli.WriteLine("Deriving keys from constants...");
    vault2Key = Crypto.DeriveKey(v2Indices, xorMask, pcgSeed);
    vault3Key = Crypto.DeriveKey(v3Indices, xorMask, pcgSeed);
}

// Decrypt the manifest or process the plugin package

if (isZip)
{
    Archive.ProcessPluginPackage(inputPath, vault2Key, vault3Key, format, outputFile);
}
else
{
    if (vault2Key is null || vault3Key is null)
    {
        Cli.WriteLine("[-] Fatal: Keys required for single-manifest decryption.");
        return 1;
    }

    Cli.WriteLine($"Reading: {inputPath}");
    byte[] fileData = File.ReadAllBytes(inputPath);

    if (!fileData[0..6].SequenceEqual(Constants.MagicElgato))
    {
        Cli.WriteLine("File does not have ELGATO header - it may already be plaintext.");
        return 1;
    }

    Cli.WriteLine($"Decrypting ({fileData.Length} bytes)...");

    byte[] plaintext;
    try
    {
        plaintext = Archive.DecryptManifest(fileData, vault2Key, vault3Key);
    }
    catch (Exception ex)
    {
        Cli.WriteLine($"[-] Decryption failed: {ex.Message}");
        return 1;
    }

    plaintext = Archive.PrettyPrintJson(plaintext);

    if (outputFile is not null)
    {
        File.WriteAllBytes(outputFile, plaintext);
        Cli.WriteLine($"Written to: {outputFile}");
    }
    else
    {
        try
        {
            Cli.WriteLine("\n--- Decrypted Content ---");
            Cli.WriteLine(System.Text.Encoding.UTF8.GetString(plaintext));
        }
        catch
        {
            Cli.WriteLine(
                $"\n[Binary output, {plaintext.Length} bytes - specify output file to save]");
        }
    }
}

return 0;
