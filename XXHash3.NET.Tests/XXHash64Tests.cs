using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XXHash3NET.Tests;

public class XXHash64Tests
{
    public class Compute
    {
        [Theory]
        [InlineData(16, 15328957957238450054)]
        [InlineData(32, 1299993213234354925)]
        [InlineData(33, 2925247938864231543)]
        [InlineData(36, 12022155075197052050)]
        public void Should_Return_Correct_Hash_For_Input_Filled_With_0x10_Of_Size(
            int size,
            ulong expectedHash
        )
        {
            // Create buffer filled with 0x10 of specified size
            byte[] buffer = new byte[size];
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = 0x10;
            }

            ulong resultHash = XXHash64.Compute(buffer);

            Assert.Equal(resultHash, expectedHash);
        }

        [Theory]
        [InlineData("assets/characters/aatrox/skins/base/aatrox.aatroxupdate.skl", 0xd72c2acbe776c1cc)]
        public void Should_Return_Correct_Hash_For_String(
            string input,
            ulong expectedHash
        )
        {
            ulong resultHash = XXHash64.Compute(input);

            Assert.Equal(resultHash, expectedHash);
        }
    }
}
