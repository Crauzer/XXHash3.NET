using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace XXHash3NET.Sandbox
{
    class Program
    {
        private static readonly (string file, string checksum) TESTSTREAM_LONG_XXH = (
            "teststream_long.xxh",
            "0x5841c4fe86cbde7e"
        );
        private static readonly (string file, string checksum) TESTSTREAM_16_XXH = (
            "teststream_16.xxh",
            "0x92e37d5dd1908b55"
        );
        private static readonly (string file, string checksum) TESTSTREAM_128_XXH = (
            "teststream_128.xxh",
            "0xb20d3315510bf903"
        );
        private static readonly (string file, string checksum) TESTSTREAM_240_XXH = (
            "teststream_240.xxh",
            "0xc7a48cec6028806a"
        );
        private static readonly (string file, string checksum) TESTSTREAM_512_XXH = (
            "teststream_512.xxh",
            "0x1543947f97a0d455"
        );

        static void Main(string[] args)
        {
            CreateTestingFiles();
            XXH3FileDigest(TESTSTREAM_LONG_XXH.file, TESTSTREAM_LONG_XXH.checksum);
            XXH3FileDigest(TESTSTREAM_16_XXH.file, TESTSTREAM_16_XXH.checksum);
            XXH3FileDigest(TESTSTREAM_128_XXH.file, TESTSTREAM_128_XXH.checksum);
            XXH3FileDigest(TESTSTREAM_240_XXH.file, TESTSTREAM_240_XXH.checksum);
            XXH3FileDigest(TESTSTREAM_512_XXH.file, TESTSTREAM_512_XXH.checksum);
        }

        static void CreateTestingFiles()
        {
            byte[] test16 = new byte[16];
            for (int i = 0; i < test16.Length; i++)
            {
                test16[i] = 0x10;
            }

            byte[] test128 = new byte[128];
            for (int i = 0; i < test128.Length; i++)
            {
                test128[i] = 0x10;
            }

            byte[] test240 = new byte[240];
            for (int i = 0; i < test240.Length; i++)
            {
                test240[i] = 0x10;
            }

            byte[] test512 = new byte[512];
            for (int i = 0; i < test512.Length; i++)
            {
                test512[i] = 0x10;
            }

            File.WriteAllBytes("teststream_16.xxh", test16);
            File.WriteAllBytes("teststream_128.xxh", test128);
            File.WriteAllBytes("teststream_240.xxh", test240);
            File.WriteAllBytes("teststream_512.xxh", test512);
        }

        static void XXH3FileDigest(string file, string originalChecksum)
        {
            using FileStream stream = File.OpenRead(file);

            ulong digest = XXHash3.Hash64(stream);

            string checksum = string.Format("0x{0:x}", digest);
            //if (checksum != originalChecksum) { }
        }
    }
}
