using System;
using System.IO;
using System.Text;

namespace XXHash3NET.Sandbox
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] xx = File.ReadAllBytes(@"C:\Users\Crauzer\Desktop\test.xxx");

            XXHash3.Hash64(xx);
        }
    }
}
