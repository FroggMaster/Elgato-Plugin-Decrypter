using System.IO.Compression;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using PeterO.Cbor;

namespace ElgatoDecrypter;

internal static class Archive
{
    // Header and entry table structures

    private record ElgatoHeader(long TotalSize, long EntriesEnd, ulong XorSeed);
    private record EntryRecord(uint Magic, long Offset, long Size);

    private static ElgatoHeader ParseHeader(byte[] data)
    {
        if (data.Length < 32)
            throw new InvalidDataException("File too small for ELGATO header");

        var magic = data[0..6];
        if (!magic.SequenceEqual(Constants.MagicElgato))
            throw new InvalidDataException(
                $"Invalid magic: {BitConverter.ToString(magic)} (expected ELGATO)");

        ushort version = BitConverter.ToUInt16(data, 6);
        if (version != 1)
            throw new InvalidDataException($"Unsupported version: {version}");

        long totalSize  = BitConverter.ToInt64(data, 8);
        long entriesEnd = BitConverter.ToInt64(data, 16);
        ulong xorSeed   = BitConverter.ToUInt64(data, 24);

        return new ElgatoHeader(totalSize, entriesEnd, xorSeed);
    }

    private static List<EntryRecord> ParseEntryTable(byte[] data)
    {
        if (data.Length % 32 != 0)
            throw new InvalidDataException(
                $"Entry table size {data.Length} is not 32-byte aligned");

        var entries = new List<EntryRecord>();
        for (int i = 0; i < data.Length; i += 32)
        {
            uint magic  = BitConverter.ToUInt32(data, i);
            long offset = BitConverter.ToInt64(data, i + 4);
            long size   = BitConverter.ToInt64(data, i + 12);
            entries.Add(new EntryRecord(magic, offset, size));
        }
        return entries;
    }

    private static EntryRecord FindEntry(List<EntryRecord> entries, uint magic)
    {
        var e = entries.FirstOrDefault(x => x.Magic == magic)
            ?? throw new InvalidDataException(
                $"Entry 0x{magic:X8} not found");
        return e;
    }

    // Decrypt an ELGATO-encrypted manifest file

    /// <summary>
    /// Decrypts an ELGATO-encrypted manifest file and returns the plaintext bytes.
    /// </summary>
    public static byte[] DecryptManifest(byte[] fileData, byte[] vault2Key, byte[] vault3Key)
    {
        // 1. Parse header
        var header = ParseHeader(fileData);

        if (header.TotalSize != fileData.Length)
            throw new InvalidDataException(
                $"Header total_size ({header.TotalSize}) != file size ({fileData.Length})");

        Cli.WriteLine(
            $"  Header: total_size={header.TotalSize}, " +
            $"entries_end={header.EntriesEnd}, xor_seed=0x{header.XorSeed:X16}");

        // 2. Read and decrypt entry table
        byte[] entryTableRaw = fileData[32..(int)header.EntriesEnd];
        byte[] entryTableDec = Crypto.PcgXorDecrypt(entryTableRaw, header.XorSeed, 32);
        var entries = ParseEntryTable(entryTableDec);

        Cli.WriteLine($"  Entries ({entries.Count}):");
        foreach (var e in entries)
        {
            string name = System.Text.Encoding.ASCII.GetString(BitConverter.GetBytes(e.Magic));
            Cli.WriteLine($"    {name} (0x{e.Magic:X8}): offset={e.Offset}, size={e.Size}");
        }

        // 3. Read and decrypt META entry
        var metaEntry  = FindEntry(entries, Constants.MagicMeta);
        long metaFilePos = header.EntriesEnd + metaEntry.Offset;
        byte[] metaRaw = fileData[(int)metaFilePos..(int)(metaFilePos + metaEntry.Size)];
        byte[] metaDec = Crypto.PcgXorDecrypt(metaRaw, header.XorSeed, metaFilePos);

        // 4. Parse META (CBOR encoded)
        var meta = CBORObject.DecodeFromBytes(metaDec);

        long dataSize  = meta["data_size"].ToObject<long>();
        long blockSize = meta["block_size"].ToObject<long>();
        byte[] ephPk      = meta["eph_pk"].GetByteString();
        byte[] appPkHash  = meta["app_pk_hash"].GetByteString();
        byte[] salt       = meta["salt"].GetByteString();

        var ivsObj  = meta["IVs"];
        var tagsObj = meta["tags"];
        var ivs  = Enumerable.Range(0, ivsObj.Count).Select(i => ivsObj[i].GetByteString()).ToList();
        var tags = Enumerable.Range(0, tagsObj.Count).Select(i => tagsObj[i].GetByteString()).ToList();

        int numBlocks = blockSize > 0 ? (int)Math.Ceiling((double)dataSize / blockSize) : 0;

        Cli.WriteLine(
            $"  META: data_size={dataSize}, block_size={blockSize}, num_blocks={numBlocks}");
        Cli.WriteLine($"    eph_pk:      {Convert.ToHexString(ephPk).ToLower()}");
        Cli.WriteLine($"    salt:        {Convert.ToHexString(salt).ToLower()}");
        Cli.WriteLine($"    app_pk_hash: {Convert.ToHexString(appPkHash).ToLower()}");
        Cli.WriteLine($"    IVs count:   {ivs.Count}");
        Cli.WriteLine($"    Tags count:  {tags.Count}");

        // 5. Verify app_pk_hash matches SHA-256(vault3_key)
        byte[] vault3Hash = SHA256.HashData(vault3Key);
        if (!vault3Hash.SequenceEqual(appPkHash))
            throw new InvalidDataException(
                $"app_pk_hash mismatch!\n" +
                $"  Expected: {Convert.ToHexString(vault3Hash).ToLower()}\n" +
                $"  Got:      {Convert.ToHexString(appPkHash).ToLower()}");

        Cli.WriteLine("  app_pk_hash verification: OK");

        // 6. Derive per-file AES key via X25519 ECDH + HKDF-SHA256
        byte[] sharedSecret = X25519(vault2Key, ephPk);
        byte[] aesKey = HkdfSha256(sharedSecret, salt, Array.Empty<byte>(), 32);

        Cli.WriteLine($"  Derived AES key: {Convert.ToHexString(aesKey).ToLower()}");

        // 7. Decrypt DATA blocks with AES-256-GCM
        var dataEntry = FindEntry(entries, Constants.MagicData);
        using var aesGcm = new AesGcm(aesKey, 16); // 16-byte tag

        var plaintextParts = new List<byte[]>();
        long remaining = dataSize;

        for (int i = 0; i < numBlocks; i++)
        {
            long blockStart      = i * blockSize;
            long thisBlockSize   = Math.Min(blockSize, remaining);
            long blockFilePos    = header.EntriesEnd + dataEntry.Offset + blockStart;

            byte[] blockRaw = fileData[(int)blockFilePos..(int)(blockFilePos + thisBlockSize)];
            byte[] blockDec = Crypto.PcgXorDecrypt(blockRaw, header.XorSeed, blockFilePos);

            byte[] iv  = ivs[i];
            byte[] tag = tags[i];

            byte[] plainBlock = new byte[blockDec.Length];
            aesGcm.Decrypt(iv, blockDec, tag, plainBlock, null);

            plaintextParts.Add(plainBlock);
            remaining -= plainBlock.Length;

            if ((i + 1) % 10 == 0 || i == numBlocks - 1)
                Cli.WriteLine($"  Decrypted block {i + 1}/{numBlocks}");
        }

        byte[] plaintext = CombineBytes(plaintextParts);
        Cli.WriteLine($"  Total decrypted size: {plaintext.Length} bytes");
        return plaintext;
    }

    // Process plugin packages (ZIP files)

    /// <summary>
    /// Returns true if the ZIP contains at least one manifest.json entry 
    /// that starts with the ELGATO magic bytes. Used to decide whether 
    /// key extraction is necessary before processing.
    /// </summary>
    public static bool ZipContainsEncryptedManifest(string pluginPath)
    {
        try
        {
            using var zip = ZipFile.OpenRead(pluginPath);
            foreach (var entry in zip.Entries)
            {
                if (!entry.FullName.EndsWith("manifest.json",
                        StringComparison.OrdinalIgnoreCase)) continue;

                using var stream = entry.Open();
                byte[] header = new byte[6];
                int read = stream.Read(header, 0, 6);
                if (read == 6 && header.SequenceEqual(Constants.MagicElgato))
                    return true;
            }
        }
        catch { /* best-effort */ }
        return false;
    }

    /// <summary>
    /// Processes a .streamDeckPlugin file (ZIP), decrypting manifest.json 
    /// and optionally converting it to a target format.
    /// When format is StreamDock, the manifest is converted using 
    /// ManifestConverter.ToStreamDock and written to a new .sdPlugin file 
    /// alongside the original (the source file is not modified).
    /// </summary>
    public static void ProcessPluginPackage(
        string pluginPath, byte[]? vault2Key, byte[]? vault3Key,
        OutputFormat format = OutputFormat.StreamDeck,
        string? outputDir = null)
    {
        Cli.WriteLine($"Processing plugin package: {pluginPath}");
        if (format == OutputFormat.StreamDock)
            Cli.WriteLine("[*] Conversion mode: Stream Dock");

        // Derive output path
        string outputPath;
        if (format == OutputFormat.StreamDock)
        {
            // Use the root folder name from inside the ZIP as the output filename,
            // since VSD Craft requires the .sdPlugin filename to match the bundle ID
            // (e.g. "com.elgato.spotify.sdPlugin" not "Spotify-2.0.2.32-mac_windows.sdPlugin").
            string bundleId;
            using (var zprobe = ZipFile.OpenRead(pluginPath))
            {
                var firstEntry = zprobe.Entries.FirstOrDefault();
                if (firstEntry is not null)
                {
                    // Root folder name is the first path segment, strip trailing slash
                    bundleId = firstEntry.FullName.Split('/')[0];
                    // Strip .sdPlugin suffix if the folder already includes it
                    if (bundleId.EndsWith(".sdPlugin", StringComparison.OrdinalIgnoreCase))
                        bundleId = bundleId[..^".sdPlugin".Length];
                }
                else
                {
                    bundleId = Path.GetFileNameWithoutExtension(pluginPath);
                }
            }
            outputPath = Path.Combine(
                Path.GetDirectoryName(pluginPath) ?? ".",
                bundleId + ".sdPlugin");
        }
        else
        {
            outputPath = pluginPath; // in-place
        }

        // Override output directory if specified
        if (outputDir is not null)
        {
            Directory.CreateDirectory(outputDir);
            outputPath = Path.Combine(outputDir, Path.GetFileName(outputPath));
        }

        string tempPath    = Path.GetTempFileName();
        string tempZipPath = tempPath + ".zip";
        File.Delete(tempPath);

        bool manifestDecrypted = false;

        try
        {
            using (var zin  = ZipFile.OpenRead(pluginPath))
            using (var zout = ZipFile.Open(tempZipPath, ZipArchiveMode.Create))
            {
                // VSD Craft requires explicit directory entries for every subdirectory
                // (not just the root) so it can reconstruct the folder tree during install.
                if (format == OutputFormat.StreamDock)
                {
                    var allDirs = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

                    foreach (var e in zin.Entries)
                    {
                        // Collect every path segment prefix that ends with '/'
                        var parts = e.FullName.Split('/');
                        for (int i = 1; i < parts.Length; i++)
                        {
                            // parts[i] is empty for the trailing slash of directory entries
                            string dirPath = string.Join("/", parts[..i]) + "/";
                            allDirs.Add(dirPath);
                        }
                    }

                    var refEntry = zin.Entries.FirstOrDefault();
                    foreach (var dir in allDirs)
                    {
                        var dirEntry = zout.CreateEntry(dir, CompressionLevel.NoCompression);
                        if (refEntry is not null)
                            dirEntry.LastWriteTime = refEntry.LastWriteTime;
                    }
                }

                foreach (var entry in zin.Entries)
                {
                    // Skip directory entries (already written above for StreamDock,
                    // not needed for StreamDeck in-place mode).
                    if (entry.FullName.EndsWith('/') && entry.Length == 0)
                        continue;

                    byte[] entryData;
                    using (var ms = new MemoryStream())
                    {
                        using var es = entry.Open();
                        es.CopyTo(ms);
                        entryData = ms.ToArray();
                    }

                    if (entry.FullName.EndsWith("manifest.json",
                            StringComparison.OrdinalIgnoreCase) &&
                        entryData.Length >= 6 &&
                        entryData[0..6].SequenceEqual(Constants.MagicElgato))
                    {
                        Cli.WriteLine($"Found encrypted manifest: {entry.FullName}");
                        try
                        {
                            if (vault2Key is null || vault3Key is null)
                                throw new InvalidOperationException(
                                    "Keys not available — cannot decrypt encrypted manifest.");

                            byte[] decrypted = DecryptManifest(entryData, vault2Key, vault3Key);
                            decrypted = PrettyPrintJson(decrypted);

                            if (format == OutputFormat.StreamDock)
                            {
                                Cli.WriteLine("  Converting manifest to Stream Dock format...");
                                decrypted = ManifestConverter.ToStreamDock(decrypted);
                                Cli.WriteLine("  Conversion OK");
                            }

                            Cli.WriteLine($"  Decrypted successfully ({decrypted.Length} bytes)");

                            var outEntry = zout.CreateEntry(entry.FullName,
                                CompressionLevel.Optimal);
                            outEntry.LastWriteTime = entry.LastWriteTime;
                            using var outs = outEntry.Open();
                            outs.Write(decrypted);
                            manifestDecrypted = true;
                            continue;
                        }
                        catch (Exception ex)
                        {
                            Cli.WriteLine(
                                $"  [-] Failed to decrypt {entry.FullName}: {ex.Message}");
                        }
                    }
                    else if (entry.FullName.EndsWith("manifest.json",
                                 StringComparison.OrdinalIgnoreCase))
                    {
                        if (format == OutputFormat.StreamDock)
                        {
                            Cli.WriteLine(
                                $"Manifest {entry.FullName} is not encrypted — converting to Stream Dock format...");
                            try
                            {
                                byte[] converted = ManifestConverter.ToStreamDock(entryData);
                                Cli.WriteLine($"  Conversion OK ({converted.Length} bytes)");

                                var outEntry = zout.CreateEntry(entry.FullName, CompressionLevel.Optimal);
                                outEntry.LastWriteTime = entry.LastWriteTime;
                                using var outs = outEntry.Open();
                                outs.Write(converted);
                                manifestDecrypted = true; // reuse flag: means "manifest was processed"
                                continue;
                            }
                            catch (Exception ex)
                            {
                                Cli.WriteLine($"  [-] Conversion failed: {ex.Message}");
                            }
                        }
                        else
                        {
                            Cli.WriteLine($"Manifest {entry.FullName} is not encrypted.");
                        }
                    }

                    // Copy original entry verbatim
                    var copyEntry = zout.CreateEntry(entry.FullName, CompressionLevel.Optimal);
                    copyEntry.LastWriteTime = entry.LastWriteTime;
                    using var copyStream = copyEntry.Open();
                    copyStream.Write(entryData);
                }
            }

            if (manifestDecrypted)
            {
                File.Move(tempZipPath, outputPath, overwrite: true);
                string action = format == OutputFormat.StreamDock ? "converted" : "decrypted";
                Cli.WriteLine($"[+] Successfully written {action} plugin to: {outputPath}");
            }
            else
            {
                Cli.WriteLine("[*] No encrypted manifest found or decryption failed. File unchanged.");
                File.Delete(tempZipPath);
            }
        }
        catch (Exception ex)
        {
            Cli.WriteLine($"[-] Error processing plugin package: {ex.Message}");
            if (File.Exists(tempZipPath)) File.Delete(tempZipPath);
        }
    }

    // Cryptographic helper functions

    /// <summary>
    /// X25519 ECDH: shared_secret = X25519(privateKey, publicKey).
    /// Uses .NET's ECDiffieHellman with the raw 32-byte X25519 scalars.
    /// </summary>
    private static byte[] X25519(byte[] privateKeyBytes, byte[] publicKeyBytes)
    {
        var privateKey = new X25519PrivateKeyParameters(privateKeyBytes, 0);
        var publicKey  = new X25519PublicKeyParameters(publicKeyBytes, 0);

        var agreement = new X25519Agreement();
        agreement.Init(privateKey);
        byte[] secret = new byte[agreement.AgreementSize];
        agreement.CalculateAgreement(publicKey, secret, 0);
        return secret;
    }

    /// <summary>
    /// HKDF-SHA256 key derivation (Extract + Expand).
    /// </summary>
    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info);
    }

    /// <summary>
    /// Re-serializes JSON bytes with indentation. Returns original bytes if not valid JSON.
    /// </summary>
    public static byte[] PrettyPrintJson(byte[] raw)
    {
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(raw);
            using var ms  = new MemoryStream();
            using var writer = new System.Text.Json.Utf8JsonWriter(
                ms, new System.Text.Json.JsonWriterOptions
                {
                    Indented = true,
                    Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                });
            doc.WriteTo(writer);
            writer.Flush();
            return ms.ToArray();
        }
        catch
        {
            return raw; // not JSON, return as-is
        }
    }

    private static byte[] CombineBytes(List<byte[]> parts)
    {
        int total = parts.Sum(p => p.Length);
        byte[] result = new byte[total];
        int offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }
        return result;
    }
}
