using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System;

namespace XXHash3NET
{
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
        internal static uint Read32Le(ReadOnlySpan<byte> data) =>
            BinaryPrimitives.ReadUInt32LittleEndian(data);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong Read64Le(ReadOnlySpan<byte> data) =>
            BinaryPrimitives.ReadUInt64LittleEndian(data);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Write32Le(Span<byte> data, uint value) =>
            BinaryPrimitives.WriteUInt32LittleEndian(data, value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void Write64Le(Span<byte> data, ulong value) =>
            BinaryPrimitives.WriteUInt64LittleEndian(data, value);
    }
}
