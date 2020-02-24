/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

using Xunit;
using System.IO;
using System.Threading.Tasks;

namespace GlitchedPolygons.Services.Cryptography.Symmetric.Tests
{
    public class SymmetricCryptographyTests
    {
        private readonly ISymmetricCryptography crypto = new SymmetricCryptography();
        private readonly string text = File.ReadAllText("TestData/LoremIpsum.txt");
        private readonly byte[] data = new byte[] { 1, 2, 3, 64, 128, 1, 3, 3, 7, 6, 9, 4, 2, 0, 1, 9, 9, 6, 58, 67, 55, 100, 96 };

        private const string ENCRYPTION_PW = "Encryption-Password_239äöü!!$°§%ç=?¨]]_\"&  &/|?´~^";
        private const string WRONG_DECRYPTION_PW = "wrong-PW__5956kjnsdjkbä$öüö¨  \n  \t zzEmDkf542";

        [Fact]
        public async Task SymmetricCryptography_EncryptStringUsingPw_DecryptStringUsingPw_IdenticalAfterwards()
        {
            string encr = await crypto.EncryptWithPasswordAsync(text, ENCRYPTION_PW);
            string decr = crypto.DecryptWithPassword(encr, ENCRYPTION_PW);

            Assert.Equal(text, decr);
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptStringUsingPw_NotIdenticalWithOriginal()
        {
            string encr = await crypto.EncryptWithPasswordAsync(text, ENCRYPTION_PW);
            Assert.NotEqual(encr, text);
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptStringUsingPw_DecryptStringUsingWrongPw_ReturnsNull()
        {
            string encr = await crypto.EncryptWithPasswordAsync(text, ENCRYPTION_PW);
            string decr = crypto.DecryptWithPassword(encr, WRONG_DECRYPTION_PW);

            Assert.NotEqual(text, decr);
            Assert.Null(decr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public async Task SymmetricCryptography_EncryptStringUsingNullOrEmptyPw_ReturnsEmptyString(string pw)
        {
            string encr = await crypto.EncryptWithPasswordAsync(text, pw);
            Assert.Empty(encr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public async Task SymmetricCryptography_EncryptNullOrEmptyString_ReturnsEmptyString(string testData)
        {
            string encr = await crypto.EncryptWithPasswordAsync(testData, ENCRYPTION_PW);
            Assert.Empty(encr);
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptBytesUsingPw_DecryptBytesUsingPw_IdenticalAfterwards()
        {
            byte[] encr = await crypto.EncryptWithPasswordAsync(data, ENCRYPTION_PW);
            byte[] decr = crypto.DecryptWithPassword(encr, ENCRYPTION_PW);

            Assert.Equal(data, decr);
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptBytesUsingPw_NotIdenticalWithOriginal()
        {
            byte[] encr = await crypto.EncryptWithPasswordAsync(data, ENCRYPTION_PW);
            Assert.NotEqual(encr, data);
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptBytesUsingPw_DecryptBytesUsingWrongPw_ReturnsNull()
        {
            byte[] encr = await crypto.EncryptWithPasswordAsync(data, ENCRYPTION_PW);
            byte[] decr = crypto.DecryptWithPassword(encr, WRONG_DECRYPTION_PW);

            Assert.NotEqual(encr, data);
            Assert.Null(decr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public async Task SymmetricCryptography_EncryptBytesUsingNullOrEmptyPw_ReturnsEmptyBytesArray(string pw)
        {
            byte[] encr = await crypto.EncryptWithPasswordAsync(data, pw);
            Assert.Empty(encr);
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        public async Task SymmetricCryptography_EncryptNullOrEmptyBytes_ReturnsEmptyBytesArray(byte[] d)
        {
            byte[] encr = await crypto.EncryptWithPasswordAsync(d, ENCRYPTION_PW);
            Assert.Empty(encr);
        }

        [Fact]
        public async Task SymmetricCryptography_Encrypt_Decrypt_IdenticalAfterwards()
        {
            EncryptionResult encr = await crypto.EncryptAsync(data);
            byte[] decr = crypto.Decrypt(encr);
            Assert.Equal(decr, data);
        }

        [Fact]
        public async Task SymmetricCryptography_Encrypt_DifferentThanOriginal()
        {
            EncryptionResult encr = await crypto.EncryptAsync(data);
            Assert.NotEqual(encr.EncryptedData, data);
        }

        [Fact]
        public async Task SymmetricCryptography_DecryptUsingNull_ReturnsEmptyBytesArray()
        {
            byte[] decr = crypto.Decrypt(null);
            Assert.Empty(decr);
        }

        [Fact]
        public async Task SymmetricCryptography_DecryptEmptyInstance_ReturnsEmptyByteArray()
        {
            byte[] decr = crypto.Decrypt(EncryptionResult.Empty);
            Assert.Empty(decr);
        }

        [Fact]
        public async Task SymmetricCryptography_Encrypt_DecryptUsingWrongData_ReturnsEmptyBytesArray()
        {
            EncryptionResult encr = await crypto.EncryptAsync(data);
            byte[] decr = crypto.Decrypt(new EncryptionResult()
            {
                IV = new byte[] {4, 5, 6},
                Key = new byte[] {1, 2, 3},
                EncryptedData = new byte[] {7, 8, 9}
            });
            Assert.False(encr.IsEmpty());
            Assert.NotEqual(decr, data);
            Assert.Null(decr);
        }
    }
}