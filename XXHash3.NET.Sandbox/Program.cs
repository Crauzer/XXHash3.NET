using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace XXHash3NET.Sandbox
{
    class Program
    {
        private static readonly (string file, string checksum) TESTSTREAM_XXH = ("teststream.xxh", "0x5841c4fe86cbde7e");

        static void Main(string[] args)
        {
            XXH3FileDigest(TESTSTREAM_XXH.file, TESTSTREAM_XXH.checksum);
        }

        static void XXH3FileDigest(string file, string originalChecksum)
        {
            using FileStream stream = File.OpenRead(file);

            ulong digest = XXHash3.Hash64(stream);

            string checksum = string.Format("0x{0:x}", digest);
            if (checksum != originalChecksum)
            {

            }
        }
    }
}
