using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;

namespace ElgatoDecrypter;

internal sealed class KeyExtractor
{
    private readonly string _binaryPath;

    public KeyExtractor(string? binaryPath = null)
    {
        _binaryPath = binaryPath ?? Constants.DefaultBinaryPath;
    }

    // Public API

    /// <summary>
    /// Extracts keys from the binary.
    /// Returns (v1Indices, v2Indices, v3Indices, xorMask, pcgSeed) or null on failure.
    /// Primary path uses structural search to locate groups of 7 consecutive
    /// movdqa xmm,[rip+disp] instructions, then reads the mov r64,imm64 seed 
    /// immediate that follows each group. This path doesn't depend on knowing 
    /// the seed value in advance, so it survives binary updates that only change 
    /// the seed constant.
    /// Fallback path does a raw byte search for Constants.PcgSeed, used when 
    /// structural search can't find exactly three agreeing groups.
    /// </summary>
    public (byte[] v1, byte[] v2, byte[] v3, byte[] xorMask, ulong pcgSeed)? Extract()
    {
        if (!File.Exists(_binaryPath))
        {
            Cli.WriteLine($"[-] Binary not found at {_binaryPath}. Cannot extract keys.");
            return null;
        }

        try
        {
            using var mmf = MemoryMappedFile.CreateFromFile(
                _binaryPath, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
            using var accessor = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read);

            long fileSize = new FileInfo(_binaryPath).Length;
            byte[] fileBytes = new byte[fileSize];
            accessor.ReadArray(0, fileBytes, 0, (int)fileSize);

            // Parse PE sections for RVA <-> offset conversions
            var sections = ParsePeSections(fileBytes);
            if (sections is null)
            {
                Cli.WriteLine("[-] Failed to parse PE sections.");
                return null;
            }

            // === PRIMARY: structural movdqa-group search ===
            var result = TryStructuralExtract(fileBytes, sections);
            if (result is not null)
                return result;

            // === FALLBACK: raw seed-byte search ===
            Cli.WriteLine("[!] Structural extraction failed — falling back to hardcoded seed search.");
            return TryLegacyExtract(fileBytes, sections);
        }
        catch (Exception ex)
        {
            Cli.WriteLine($"[-] Extraction failed: {ex.Message}");
            return null;
        }
    }

    // Structural extraction (primary path)

    /// <summary>
    /// Finds all groups of minCount or more movdqa xmm,[rip+disp32] instructions 
    /// whose first and last positions are within windowSize raw file bytes of 
    /// each other. Groups are non-overlapping; once a group is accepted the scan 
    /// advances past its last member.
    /// </summary>
    private static List<List<int>> FindMovdqaGroups(
        byte[] data, int minCount = 7, int windowSize = 300)
    {
        // Collect every movdqa xmm,[rip+disp32] position in the file.
        // Opcode: 66 0F 6F /r  where (ModRM & 0xC7) == 0x05.
        var all = new List<int>();
        for (int i = 0; i < data.Length - 4; i++)
        {
            if (data[i]     == 0x66 &&
                data[i + 1] == 0x0F &&
                data[i + 2] == 0x6F &&
                (data[i + 3] & 0xC7) == 0x05)
                all.Add(i);
        }

        // Group consecutive positions that are all within windowSize of the
        // group's first position. Non-overlapping: once a group is accepted
        // the scan index jumps past the group.
        var groups = new List<List<int>>();
        int idx = 0;
        while (idx < all.Count)
        {
            var group = new List<int> { all[idx] };
            int j = idx + 1;
            while (j < all.Count && all[j] - all[idx] <= windowSize)
                group.Add(all[j++]);

            if (group.Count >= minCount)
            {
                groups.Add(group);
                idx = j; // skip past accepted group
            }
            else
            {
                idx++;
            }
        }
        return groups;
    }

    /// <summary>
    /// After the last movdqa in the group, scans forward up to 300 bytes for 
    /// every mov r64, imm64 instruction (REX.W B8+rd imm64) and returns all of them.
    /// The vault functions contain at least two such immediates before the PCG seed: 
    /// one non-seed constant appears ~20 bytes after the last movdqa, and the actual 
    /// PCG seed appears ~200 bytes later. Returning all candidates lets the outer loop 
    /// probe each value against the XOR-mask check to determine which one is real.
    /// </summary>
    private static List<(ulong seed, int instrOffset)> FindSeedCandidatesInGroup(
        byte[] data, List<int> group)
    {
        // Each movdqa xmm,[rip+disp32] is exactly 8 bytes.
        int scanStart = group[^1] + 8;
        int scanEnd   = Math.Min(data.Length - 10, scanStart + 300);

        var results = new List<(ulong seed, int instrOffset)>();
        for (int pos = scanStart; pos < scanEnd; pos++)
        {
            // REX.W prefix: 0x48 (no extension bits) or 0x49 (REX.B)
            byte rex = data[pos];
            if (rex != 0x48 && rex != 0x49) continue;

            // B8..BF = MOV r64, imm64
            byte opcode = data[pos + 1];
            if (opcode < 0xB8 || opcode > 0xBF) continue;

            ulong val = BitConverter.ToUInt64(data, pos + 2);
            if (val != 0 && val != ulong.MaxValue)
                results.Add((val, pos));
        }
        return results;
    }

    private (byte[] v1, byte[] v2, byte[] v3, byte[] xorMask, ulong pcgSeed)?
        TryStructuralExtract(byte[] fileBytes, List<PeSection> sections)
    {
        var groups = FindMovdqaGroups(fileBytes);
        if (groups.Count < 3)
        {
            Cli.WriteLine(
                $"[!] Structural search: found {groups.Count} movdqa group(s), need ≥ 3.");
            return null;
        }

        Cli.WriteLine(
            $"[+] Structural search: found {groups.Count} movdqa group(s).");

        // For every group collect ALL mov r64,imm64 immediates that follow it.
        // Each vault function contains at least four: one non-seed constant
        // ~20 bytes after the last movdqa, then PcgInc / PcgSeed / PcgMult as
        // a tight triplet ~200 bytes later.
        //
        // Discriminator: PcgSeed is the ONLY value that has another
        // mov r64,imm64 instruction exactly 10 bytes before it (PcgInc loads
        // directly into the preceding slot with no padding).  We flag these
        // as "confirmed" and sort them first.
        var seedResults = new List<(List<int> group, ulong seed, int instrOffset, bool confirmed)>();
        foreach (var group in groups)
        {
            foreach (var (seed, instrOffset) in FindSeedCandidatesInGroup(fileBytes, group))
            {
                bool confirmed = false;
                if (instrOffset >= 10)
                {
                    byte prevRex    = fileBytes[instrOffset - 10];
                    byte prevOpcode = fileBytes[instrOffset - 9];
                    confirmed = (prevRex == 0x48 || prevRex == 0x49)
                             && prevOpcode >= 0xB8 && prevOpcode <= 0xBF;
                }
                seedResults.Add((group, seed, instrOffset, confirmed));
            }
        }

        if (seedResults.Count < 3)
        {
            Cli.WriteLine(
                $"[!] Structural search: only {seedResults.Count} group(s) yielded a seed immediate.");
            return null;
        }

        // Group by seed value; confirmed candidates (PcgSeed preceded by PcgInc)
        // are sorted first, then by frequency.
        var seedCandidates = seedResults
            .GroupBy(r => r.seed)
            .Select(g => (
                seed:      g.Key,
                count:     g.Count(),
                confirmed: g.Any(r => r.confirmed),
                items:     g.OrderBy(r => r.instrOffset).ToList()))
            .Where(x => x.count >= 3)
            .OrderByDescending(x => x.confirmed)   // confirmed first
            .ThenByDescending(x => x.count)
            .ToList();

        if (seedCandidates.Count == 0)
        {
            Cli.WriteLine(
                "[!] Structural search: no seed value occurs in 3 or more groups — ambiguous.");
            return null;
        }

        foreach (var candidate in seedCandidates)
        {
            ulong extractedSeed = candidate.seed;
            var vaults = candidate.items.TakeLast(3).ToList();

            Cli.WriteLine(
                $"[*] Trying structural candidate seed 0x{extractedSeed:X16} " +
                $"({candidate.count} group(s), PcgInc-confirmed: {candidate.confirmed})...");

            try
            {
                byte[] v3Indices = ExtractIndicesFromGroup(fileBytes, sections, vaults[0].group);
                byte[] v2Indices = ExtractIndicesFromGroup(fileBytes, sections, vaults[1].group);
                byte[] v1Indices = ExtractIndicesFromGroup(fileBytes, sections, vaults[2].group);

                // instrOffset is the REX prefix; +2 = start of the 8-byte immediate,
                // which is exactly where the legacy FindAll search lands too.
                byte[] xorMask = ExtractXorMask(fileBytes, sections, vaults[0].instrOffset + 2);

                if (extractedSeed != Constants.PcgSeed)
                    Cli.WriteLine(
                        $"[!] Seed 0x{extractedSeed:X16} differs from the compile-time constant — " +
                        "the binary has been updated.");

                Cli.WriteLine(
                    $"[+] Dynamically extracted PCG seed: 0x{extractedSeed:X16}");
                Cli.WriteLine(
                    "[+] Successfully extracted all constants from binary (structural path).");
                return (v1Indices, v2Indices, v3Indices, xorMask, extractedSeed);
            }
            catch (Exception ex)
            {
                Cli.WriteLine($"[!] Candidate 0x{extractedSeed:X16} failed: {ex.Message} — trying next.");
            }
        }

        Cli.WriteLine("[!] Structural search: all candidates failed.");
        return null;
    }

    // Legacy extraction (fallback path)

    private static (byte[] v1, byte[] v2, byte[] v3, byte[] xorMask, ulong pcgSeed)?
        TryLegacyExtract(byte[] fileBytes, List<PeSection> sections)
    {
        byte[] seedBytes = BitConverter.GetBytes(Constants.PcgSeed);
        var matches = FindAll(fileBytes, seedBytes);

        if (matches.Count < 3)
        {
            Cli.WriteLine(
                $"[-] Legacy search: found {matches.Count} PCG seed match(es), expected ≥ 3.");
            return null;
        }

        Cli.WriteLine(
            $"[+] Legacy search: found {matches.Count} PCG seed match(es). Extracting constants...");

        matches.Sort();
        int v3Offset = matches[0];
        int v2Offset = matches[1];
        int v1Offset = matches[2];

        try
        {
            Cli.WriteLine("[*] Extracting Vault 3 (Public) indices...");
            byte[] v3Indices = ExtractIndices(fileBytes, sections, v3Offset);

            Cli.WriteLine("[*] Extracting Vault 2 (Private) indices...");
            byte[] v2Indices = ExtractIndices(fileBytes, sections, v2Offset);

            Cli.WriteLine("[*] Extracting Vault 1 (Signing) indices...");
            byte[] v1Indices = ExtractIndices(fileBytes, sections, v1Offset);

            Cli.WriteLine("[*] Extracting XOR Mask...");
            byte[] xorMask = ExtractXorMask(fileBytes, sections, v3Offset);

            Cli.WriteLine("[+] Successfully extracted all constants from binary (legacy path).");
            return (v1Indices, v2Indices, v3Indices, xorMask, Constants.PcgSeed);
        }
        catch (Exception ex)
        {
            Cli.WriteLine($"[-] Legacy extraction error: {ex.Message}");
            return null;
        }
    }

    // PE parsing functions

    private record PeSection(uint VAddr, uint RawSize, uint RawPtr);

    private static List<PeSection>? ParsePeSections(byte[] data)
    {
        try
        {
            if (data[0] != 'M' || data[1] != 'Z')
                throw new InvalidDataException("Not a valid PE file");

            uint eLfanew = BitConverter.ToUInt32(data, 0x3C);

            if (data[eLfanew] != 'P' || data[eLfanew + 1] != 'E' ||
                data[eLfanew + 2] != 0  || data[eLfanew + 3] != 0)
                throw new InvalidDataException("Invalid PE signature");

            ushort numSections    = BitConverter.ToUInt16(data, (int)(eLfanew + 4 + 2));
            ushort sizeOptHeader  = BitConverter.ToUInt16(data, (int)(eLfanew + 4 + 16));
            int sectionTableOff   = (int)(eLfanew + 0x18 + sizeOptHeader);

            var sections = new List<PeSection>();
            for (int i = 0; i < numSections; i++)
            {
                int entry = sectionTableOff + i * 40;
                uint vAddr   = BitConverter.ToUInt32(data, entry + 12);
                uint rawSize = BitConverter.ToUInt32(data, entry + 16);
                uint rawPtr  = BitConverter.ToUInt32(data, entry + 20);
                sections.Add(new PeSection(vAddr, rawSize, rawPtr));
            }
            return sections;
        }
        catch (Exception ex)
        {
            Cli.WriteLine($"[-] PE parsing failed: {ex.Message}");
            return null;
        }
    }

    private static uint? OffsetToRva(List<PeSection> sections, int offset)
    {
        foreach (var s in sections)
            if (s.RawPtr <= offset && offset < s.RawPtr + s.RawSize)
                return s.VAddr + (uint)(offset - s.RawPtr);
        return null;
    }

    private static int? RvaToOffset(List<PeSection> sections, uint rva)
    {
        foreach (var s in sections)
            if (s.VAddr <= rva && rva < s.VAddr + s.RawSize)
                return (int)(s.RawPtr + (rva - s.VAddr));
        return null;
    }

    // Key extraction helper functions

    /// <summary>
    /// Extracts 32 index bytes from a pre-identified group of movdqa positions
    /// (used by the structural extraction path).
    /// </summary>
    private static byte[] ExtractIndicesFromGroup(
        byte[] data, List<PeSection> sections, List<int> group)
    {
        var relevantLocs = group.TakeLast(7).ToList();
        return ReadIndicesFromLocs(data, sections, relevantLocs);
    }

    /// <summary>
    /// Scans backwards from seed for 7 movdqa xmm,[rip+disp] instructions.
    /// Opcode: 66 0F 6F /r  where ModRM & 0xC7 == 0x05 (RIP-relative).
    /// Used by the legacy extraction path.
    /// </summary>
    private static byte[] ExtractIndices(byte[] data, List<PeSection> sections, int seedOffset)
    {
        int startSearch = Math.Max(0, seedOffset - 300);
        int chunkLen    = seedOffset - startSearch;

        var movdqaLocs = new List<int>();
        for (int op = 0; op < chunkLen - 3; op++)
        {
            if (data[startSearch + op]     == 0x66 &&
                data[startSearch + op + 1] == 0x0F &&
                data[startSearch + op + 2] == 0x6F)
            {
                byte modrm = data[startSearch + op + 3];
                if ((modrm & 0xC7) == 0x05)
                    movdqaLocs.Add(startSearch + op);
            }
        }

        if (movdqaLocs.Count < 7)
            throw new InvalidDataException(
                $"Found only {movdqaLocs.Count} movdqa instructions before seed");

        return ReadIndicesFromLocs(data, sections, movdqaLocs.TakeLast(7).ToList());
    }

    /// <summary>
    /// Shared implementation: follows RIP-relative displacements in the given
    /// list of movdqa locations and collects the 16-byte XMM data each one
    /// references, returning the first 32 bytes.
    /// </summary>
    private static byte[] ReadIndicesFromLocs(
        byte[] data, List<PeSection> sections, List<int> locs)
    {
        var indices = new List<byte>(32);

        foreach (int loc in locs)
        {
            int dispOffset = loc + 4;
            int disp       = BitConverter.ToInt32(data, dispOffset);

            int nextInstrOffset = loc + 8;
            uint? nextInstrRva  = OffsetToRva(sections, nextInstrOffset)
                ?? throw new InvalidDataException(
                    $"Could not map instruction offset {nextInstrOffset} to RVA");

            uint targetRva    = (uint)((int)nextInstrRva + disp);
            int? targetOffset = RvaToOffset(sections, targetRva)
                ?? throw new InvalidDataException(
                    $"Could not map target RVA {targetRva} to offset");

            indices.AddRange(data[targetOffset.Value..(targetOffset.Value + 16)]);
        }

        return indices.Take(32).ToArray();
    }

    /// <summary>
    /// Scans forward from seed for LEA instruction loading the XOR mask.
    /// Pattern: [48|4C] 8D /r  where ModRM & 0xC7 == 0x05 (RIP-relative).
    /// </summary>
    private static byte[] ExtractXorMask(byte[] data, List<PeSection> sections, int seedOffset)
    {
        int limit = Math.Min(data.Length, seedOffset + 400);

        for (int pos = seedOffset; pos < limit; pos++)
        {
            if (data[pos] != 0x8D) continue;
            if (pos == 0) continue;

            byte prefix = data[pos - 1];
            if (prefix != 0x48 && prefix != 0x4C) continue;

            if (pos + 1 >= limit) continue;
            byte modrm = data[pos + 1];
            if ((modrm & 0xC7) != 0x05) continue;

            int leaStart   = pos - 1;
            int dispOffset = leaStart + 3;
            if (dispOffset + 4 > data.Length) continue;

            int disp              = BitConverter.ToInt32(data, dispOffset);
            int nextInstrOffset   = leaStart + 7;
            uint? nextInstrRva    = OffsetToRva(sections, nextInstrOffset);
            if (nextInstrRva is null) continue;

            uint targetRva    = (uint)((int)nextInstrRva + disp);
            int? targetOffset = RvaToOffset(sections, targetRva);
            if (targetOffset is null) continue;

            return data[targetOffset.Value..(targetOffset.Value + 32)];
        }

        throw new InvalidDataException("Could not find XOR mask LEA instruction");
    }

    // Helper functions for byte searching

    private static List<int> FindAll(byte[] haystack, byte[] needle)
    {
        var results = new List<int>();
        int start = 0;
        while (true)
        {
            int idx = IndexOf(haystack, needle, start);
            if (idx == -1) break;
            results.Add(idx);
            start = idx + 1;
        }
        return results;
    }

    private static int IndexOf(byte[] haystack, byte[] needle, int start)
    {
        int limit = haystack.Length - needle.Length;
        for (int i = start; i <= limit; i++)
        {
            bool found = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { found = false; break; }
            }
            if (found) return i;
        }
        return -1;
    }
}
