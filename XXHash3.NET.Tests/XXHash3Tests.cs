namespace XXHash3NET.Tests
{
    public class XXHash3Tests
    {
        [Theory]
        [InlineData(16, "0x92e37d5dd1908b55")]
        [InlineData(128, "0xb20d3315510bf903")]
        [InlineData(240, "0xc7a48cec6028806a")]
        [InlineData(512, "0x1543947f97a0d455")]
        public void Should_Return_Correct_Checksum64_For_Stream_Filled_With_0x10_Of_Size(
            int size,
            string expectedChecksum
        )
        {
            // Create buffer filled with 0x10 of specified size
            byte[] buffer = new byte[size];
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = 0x10;
            }

            // Stream over the test buffer
            using MemoryStream bufferStream = new(buffer);
            ulong digest = XXHash3.Hash64(bufferStream);
            string digestChecksumString = string.Format("0x{0:x}", digest);

            Assert.Equal(digestChecksumString, expectedChecksum);
        }

        [Theory]
        [InlineData(16, "0x92e37d5dd1908b55")]
        [InlineData(128, "0xb20d3315510bf903")]
        [InlineData(240, "0xc7a48cec6028806a")]
        [InlineData(512, "0x1543947f97a0d455")]
        public void Should_Return_Correct_Hash64_For_Input_Filled_With_0x10_Of_Size(
            int size,
            string expectedHash
        )
        {
            // Create buffer filled with 0x10 of specified size
            byte[] buffer = new byte[size];
            for (int i = 0; i < buffer.Length; i++)
            {
                buffer[i] = 0x10;
            }

            ulong resultHash = XXHash3.Hash64(buffer);
            string resultHashString = string.Format("0x{0:x}", resultHash);

            Assert.Equal(resultHashString, expectedHash);
        }
    }
}
