using System;
using System.Text;

namespace XXHash3.NET.Sandbox
{
    class Program
    {
        static void Main(string[] args)
        {
            ulong x = XXHash3.Hash64(Encoding.UTF8.GetBytes("ABCDEF"));
            string g = $"{x:x16}";
        }
    }
}
