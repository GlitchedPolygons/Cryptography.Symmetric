/*
   Copyright 2019 Raphael Beck

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
using System;
using System.IO;
using System.Threading.Tasks;

namespace GlitchedPolygons.Services.Cryptography.Symmetric.Tests
{
    public class SymmetricCryptographyTestsAsync
    {
        private readonly ISymmetricCryptography crypto = new SymmetricCryptography();
        private readonly string text = File.ReadAllText("TestData/LoremIpsum.txt");
        private readonly byte[] data = new byte[] { 1, 2, 3, 64, 128, 1, 3, 3, 7, 6, 9, 4, 2, 0, 1, 9, 9, 6, 58, 67, 55, 100, 96 };

        private const string ENCRYPTION_PW = "encryption-password_239äöü!!$°§%ç&";
        private const string WRONG_DECRYPTION_PW = "wrong-pw__5956kjnsdjkbä$öüö¨  \n  \t zzEmDkf542";

        [Fact]
        public async Task SymmetricCryptography_EncryptStringUsingPw_DecryptStringUsingPw_IdenticalAfterwards()
        {
            string encr = await crypto.EncryptWithPasswordAsync(text, ENCRYPTION_PW);
            string decr = crypto.DecryptWithPassword(encr, ENCRYPTION_PW);

            Assert.Equal(text, decr);
        }

        [Fact]
        public void SymmetricCryptography_EncryptStringUsingPw_NotIdenticalWithOriginal()
        {
            string encr = crypto.EncryptWithPassword(text, ENCRYPTION_PW);
            Assert.NotEqual(encr, text);
        }

        [Fact]
        public void SymmetricCryptography_EncryptStringUsingPw_DecryptStringUsingWrongPw_ReturnsNull()
        {
            string encr = crypto.EncryptWithPassword(text, ENCRYPTION_PW);
            string decr = crypto.DecryptWithPassword(encr, WRONG_DECRYPTION_PW);

            Assert.NotEqual(text, decr);
            Assert.Null(decr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void SymmetricCryptography_EncryptStringUsingNullOrEmptyPw_ReturnsEmptyString(string pw)
        {
            string encr = crypto.EncryptWithPassword(text, pw);
            Assert.Empty(encr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void SymmetricCryptography_EncryptNullOrEmptyString_ReturnsEmptyString(string testData)
        {
            string encr = crypto.EncryptWithPassword(testData, ENCRYPTION_PW);
            Assert.Empty(encr);
        }

        [Fact]
        public void SymmetricCryptography_EncryptBytesUsingPw_DecryptBytesUsingPw_IdenticalAfterwards()
        {
            byte[] encr = crypto.EncryptWithPassword(data, ENCRYPTION_PW);
            byte[] decr = crypto.DecryptWithPassword(encr, ENCRYPTION_PW);

            Assert.Equal(data, decr);
        }

        [Fact]
        public void SymmetricCryptography_EncryptBytesUsingPw_NotIdenticalWithOriginal()
        {
            byte[] encr = crypto.EncryptWithPassword(data, ENCRYPTION_PW);
            Assert.NotEqual(encr, data);
        }

        [Fact]
        public void SymmetricCryptography_EncryptBytesUsingPw_DecryptBytesUsingWrongPw_ReturnsNull()
        {
            byte[] encr = crypto.EncryptWithPassword(data, ENCRYPTION_PW);
            byte[] decr = crypto.DecryptWithPassword(encr, WRONG_DECRYPTION_PW);

            Assert.NotEqual(encr, data);
            Assert.Null(decr);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public void SymmetricCryptography_EncryptBytesUsingNullOrEmptyPw_ReturnsEmptyBytesArray(string pw)
        {
            byte[] encr = crypto.EncryptWithPassword(data, pw);
            Assert.Empty(encr);
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        public void SymmetricCryptography_EncryptNullOrEmptyBytes_ReturnsEmptyBytesArray(byte[] d)
        {
            byte[] encr = crypto.EncryptWithPassword(d, ENCRYPTION_PW);
            Assert.Empty(encr);
        }

        [Fact]
        public void SymmetricCryptography_Encrypt_Decrypt_IdenticalAfterwards()
        {
            EncryptionResult encr = crypto.Encrypt(data);
            byte[] decr = crypto.Decrypt(encr);
            Assert.Equal(decr, data);
        }

        [Fact]
        public void SymmetricCryptography_Encrypt_DifferentThanOriginal()
        {
            EncryptionResult encr = crypto.Encrypt(data);
            Assert.NotEqual(encr.EncryptedData, data);
        }

        [Fact]
        public void SymmetricCryptography_DecryptUsingNull_ReturnsEmptyBytesArray()
        {
            byte[] decr = crypto.Decrypt(null);
            Assert.Empty(decr);
        }

        [Fact]
        public void SymmetricCryptography_DecryptEmptyInstance_ReturnsEmptyByteArray()
        {
            byte[] decr = crypto.Decrypt(EncryptionResult.Empty);
            Assert.Empty(decr);
        }

        [Fact]
        public void SymmetricCryptography_Encrypt_DecryptUsingWrongData_ReturnsEmptyBytesArray()
        {
            EncryptionResult encr = crypto.Encrypt(data);
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