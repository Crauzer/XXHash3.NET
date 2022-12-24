using System;
using System.IO;
using System.Text;

namespace XXHash3NET.Sandbox
{
    class Program
    {
        static void Main(string[] args)
        {
            XXH3FileDigest("teststream.xxh");
        }

        static void XXH3FileDigest(string file)
        {
            using FileStream stream = File.OpenRead(file);

            ulong digest = XXHash3.Hash64(stream);
            
        }
    }
}
