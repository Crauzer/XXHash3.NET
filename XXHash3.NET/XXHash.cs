using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace XXHash3NET;

internal sealed class XXHash
{
    internal const uint XXH_PRIME32_1 = 0x9E3779B1U;
    internal const uint XXH_PRIME32_2 = 0x85EBCA77U;
    internal const uint XXH_PRIME32_3 = 0xC2B2AE3DU;
    internal const uint XXH_PRIME32_4 = 0x27D4EB2FU;
    internal const uint XXH_PRIME32_5 = 0x165667B1U;

    internal const ulong XXH_PRIME64_1 = 0x9E3779B185EBCA87UL;
    internal const ulong XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4FUL;
    internal const ulong XXH_PRIME64_3 = 0x165667B19E3779F9UL;
    internal const ulong XXH_PRIME64_4 = 0x85EBCA77C2B2AE63UL;
    internal const ulong XXH_PRIME64_5 = 0x27D4EB2F165667C5UL;

    internal const int XXH_STRIPE_LEN = 64;
    internal const int XXH_SECRET_CONSUME_RATE = 8;

    // -------------- UTILITY METHODS -------------- \\
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint Read32Le(ReadOnlySpan<byte> source) =>
        BinaryPrimitives.ReadUInt32LittleEndian(source);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong Read64Le(ReadOnlySpan<byte> source) =>
        BinaryPrimitives.ReadUInt64LittleEndian(source);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void Write32Le(Span<byte> destination, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination, value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void Write64Le(Span<byte> destination, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(destination, value);

    #region Common bit twiddling utilities
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint Swap32(uint value) => BinaryPrimitives.ReverseEndianness(value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong Swap64(ulong value) => BinaryPrimitives.ReverseEndianness(value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong RotLeft64(ulong value, int shift) =>
        (value << shift) | (value >> (64 - shift));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static ulong RotRight64(ulong value, int shift) =>
        (value << (64 - shift)) | (value >> shift);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static byte _mm_shuffle(byte p3, byte p2, byte p1, byte p0) =>
        (byte)((p3 << 6) | (p2 << 4) | (p1 << 2) | p0);
    #endregion
}
