namespace ElgatoDecrypter;

internal static class Crypto
{
    /// <summary>
    /// Non-standard PCG XSH-RR 64->32 implementation.
    /// The XSH intermediate uses a 37-bit value (not masked to 32 bits) 
    /// before rotation, then truncates to 32 bits.
    /// </summary>
    public static (uint output, ulong newState) PcgNext(ulong state)
    {
        int rot = (int)(state >> 59) & 0x1F;
        ulong xsh = (state ^ (state >> 18)) >> 27; // 37-bit, NOT masked to 32
        int negRot = (-rot) & 0x1F;
        uint part1 = (uint)(xsh >> rot);
        uint part2 = (uint)(xsh << negRot);
        uint output = part1 | part2;
        ulong newState = unchecked(Constants.PcgMult * state + Constants.PcgInc);
        return (output, newState);
    }

    /// <summary>
    /// Derives a 32-byte AES key using PCG-driven Fisher-Yates shuffle and XOR mask.
    /// </summary>
    /// <param name="pcgSeed">
    /// The PCG initial state extracted from the binary. Pass Constants.PcgSeed 
    /// only as a last resort. Prefer the value returned by KeyExtractor.Extract() 
    /// to keep the tool working when Elgato ships a binary with a different seed.
    /// </param>
    public static byte[] DeriveKey(byte[] indices, byte[] xorMask, ulong pcgSeed)
    {
        ulong state = pcgSeed;

        // Fisher-Yates shuffle on identity permutation (uses % i, not % (i+1))
        int[] perm = new int[256];
        for (int i = 0; i < 256; i++) perm[i] = i;

        for (int i = 255; i > 0; i--)
        {
            (uint output, ulong newState) = PcgNext(state);
            state = newState;
            int j = (int)(output % (uint)i);
            (perm[i], perm[j]) = (perm[j], perm[i]);
        }

        // Build inverse permutation
        int[] invPerm = new int[256];
        for (int i = 0; i < 256; i++)
            invPerm[perm[i]] = i;

        // Derive key bytes
        byte[] key = new byte[32];
        for (int k = 0; k < 32; k++)
            key[k] = (byte)(xorMask[k] ^ invPerm[indices[k]]);

        return key;
    }

    /// <summary>
    /// Advances PCG state by the specified distance using binary exponentiation.
    /// </summary>
    public static ulong PcgAdvance(ulong state, ulong distance,
        ulong mult = Constants.PcgMult, ulong inc = Constants.PcgInc)
    {
        ulong multAcc = 1;
        ulong incAcc  = 0;
        ulong curMult = mult;
        ulong curInc  = inc;
        ulong n = distance;

        while (n > 0)
        {
            if ((n & 1) != 0)
            {
                multAcc = unchecked(multAcc * curMult);
                incAcc  = unchecked(curInc + curMult * incAcc);
            }
            curInc  = unchecked(curInc * (curMult + 1));
            curMult = unchecked(curMult * curMult);
            n >>= 1;
        }

        return unchecked(incAcc + state * multAcc);
    }

    /// <summary>
    /// XOR-decrypts data using PCG stream cipher at the given file offset.
    /// Mirrors the non-standard 37-bit XSH variant used in the binary (not masked to 32 bits).
    /// </summary>
    public static byte[] PcgXorDecrypt(ReadOnlySpan<byte> data, ulong seed, long fileOffset)
    {
        if (seed == 0)
            return data.ToArray();

        // Initialize PCG state from seed
        ulong state = unchecked(Constants.PcgMult * seed + Constants.XorInitConst);

        // Compute advance distance
        ulong h = seed ^ (seed >> 16);
        h ^= h >> 32;
        ulong advanceDist = (ulong)fileOffset + (h & 0xFFFF);

        state = PcgAdvance(state, advanceDist);

        // Generate keystream and XOR
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            int rot    = (int)(state >> 59) & 0x1F;
            ulong xsh  = (state ^ (state >> 18)) >> 27; // 37-bit, NOT masked
            int negRot = (-rot) & 0x1F;
            ulong output = (xsh >> rot) | (xsh << negRot);
            result[i] = (byte)(data[i] ^ (byte)(output & 0xFF));
            state = unchecked(Constants.PcgMult * state + Constants.PcgInc);
        }

        return result;
    }
}
