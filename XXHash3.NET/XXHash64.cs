using System;
using System.Text;

namespace XXHash3NET;

/// <summary>
/// Provides an interface for computing a 64-bit XXHash
/// </summary>
public static class XXHash64
{
    /// <summary>
    /// Computes a 64-bit XXHash using the specified parameters
    /// </summary>
    /// <param name="data">The data to compute a hash from</param>
    /// <param name="seed">The seed to use</param>
    /// <returns>The computed hash</returns>
    public static ulong Compute(ReadOnlySpan<char> data, ulong seed = 0)
    {
        Span<byte> encodedData = stackalloc byte[data.Length];

        Encoding.UTF8.GetBytes(data, encodedData);

        return Compute(encodedData, seed);
    }

    /// <summary>
    /// Computes a 64-bit XXHash using the specified parameters
    /// </summary>
    /// <param name="data">The data to compute a hash from</param>
    /// <param name="seed">The seed to use</param>
    /// <returns>The computed hash</returns>
    public static ulong Compute(ReadOnlySpan<byte> data, ulong seed = 0)
    {
        ulong result;
        int offset = 0;

        if (data.Length >= 32)
        {
            ulong s1 = seed + XXHash.XXH_PRIME64_1 + XXHash.XXH_PRIME64_2;
            ulong s2 = seed + XXHash.XXH_PRIME64_2;
            ulong s3 = seed;
            ulong s4 = seed - XXHash.XXH_PRIME64_1;

            while (offset + 32 <= data.Length)
            {
                s1 = xxh64_round(s1, XXHash.Read64Le(data.Slice(offset, 8)));
                s2 = xxh64_round(s2, XXHash.Read64Le(data.Slice(offset + 8, 8)));
                s3 = xxh64_round(s3, XXHash.Read64Le(data.Slice(offset + 16, 8)));
                s4 = xxh64_round(s4, XXHash.Read64Le(data.Slice(offset + 24, 8)));

                offset += 32;
            }

            result =
                XXHash.RotLeft64(s1, 1)
                + XXHash.RotLeft64(s2, 7)
                + XXHash.RotLeft64(s3, 12)
                + XXHash.RotLeft64(s4, 18);

            result = xxh64_mergeround(result, s1);
            result = xxh64_mergeround(result, s2);
            result = xxh64_mergeround(result, s3);
            result = xxh64_mergeround(result, s4);
        }
        else
        {
            result = seed + XXHash.XXH_PRIME64_5;
        }

        result += (ulong)data.Length;

        return xxh64_finalize(result, data[offset..]);
    }

    private static ulong xxh64_finalize(ulong result, ReadOnlySpan<byte> data)
    {
        int offset = 0;

        while (offset + 8 <= data.Length)
        {
            result ^=
                XXHash.RotLeft64(XXHash.Read64Le(data[offset..]) * XXHash.XXH_PRIME64_2, 31)
                * XXHash.XXH_PRIME64_1;
            result = XXHash.RotLeft64(result, 27) * XXHash.XXH_PRIME64_1 + XXHash.XXH_PRIME64_4;
            offset += 8;
        }
        while (offset + 4 <= data.Length)
        {
            result ^= XXHash.Read32Le(data[offset..]) * XXHash.XXH_PRIME64_1;
            result = XXHash.RotLeft64(result, 23) * XXHash.XXH_PRIME64_2 + XXHash.XXH_PRIME64_3;
            offset += 4;
        }
        while (offset != data.Length)
        {
            result ^= data[offset] * XXHash.XXH_PRIME64_5;
            result = XXHash.RotLeft64(result, 11) * XXHash.XXH_PRIME64_1;
            offset++;
        }

        result ^= result >> 33;
        result *= XXHash.XXH_PRIME64_2;
        result ^= result >> 29;
        result *= XXHash.XXH_PRIME64_3;
        result ^= result >> 32;

        return result;
    }

    private static ulong xxh64_round(ulong acc, ulong input)
    {
        acc += input * XXHash.XXH_PRIME64_2;
        acc = XXHash.RotLeft64(acc, 31);
        acc *= XXHash.XXH_PRIME64_1;

        return acc;
    }

    private static ulong xxh64_mergeround(ulong acc, ulong value)
    {
        acc ^= xxh64_round(0, value);

        return acc * XXHash.XXH_PRIME64_1 + XXHash.XXH_PRIME64_4;
    }
}
