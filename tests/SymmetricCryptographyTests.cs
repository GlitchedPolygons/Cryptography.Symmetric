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
using System.Collections.Generic;

namespace GlitchedPolygons.Services.Cryptography.Symmetric.Tests
{
    public class SymmetricCryptographyTests
    {
        private readonly ISymmetricCryptography crypto = new SymmetricCryptography();

        private readonly IEnumerable<string> stringTests = new[]
        {
            File.ReadAllText("TestData/LoremIpsum.txt"),
            "e",
            "extr",
            "extremely short string",
            "...",
            "sP€$haL chAräkkteRzz m8 *ç%%%&ç/+\"*çäöü]][{}] \\  \t       \n \r  \r\t\nn yeeaH 99=='''^^^3'^'2^'3äö$$¨ !1154/1§§°°"
        };

        private readonly IEnumerable<byte[]> binaryTests = new[]
        {
            File.ReadAllBytes("TestData/Test.bin"),
            File.ReadAllBytes("TestData/LargeTest.bin"),
            new byte[] { 1, 2, 3, 64, 128, 1, 3, 3, 7, 6, 9, 4, 2, 0, 1, 9, 9, 6, 58, 67, 55, 100, 96 }
        };

        private const string ENCRYPTION_PW = "Encryption-Password_239äöü!!$°§%ç=?¨]]_\"&  &/|?´~^";
        private const string WRONG_DECRYPTION_PW = "wrong-PW__5956kjnsdjkbä$öüö¨  \n  \t zzEmDkf542";

        [Fact]
        public async Task SymmetricCryptography_EncryptStringUsingPw_DecryptStringUsingPw_IdenticalAfterwards()
        {
            foreach (string testText in stringTests)
            {
                string encr;
                string decr;

                encr = crypto.EncryptWithPassword(testText, ENCRYPTION_PW);
                decr = crypto.DecryptWithPassword(encr, ENCRYPTION_PW);

                Assert.Equal(testText, decr);

                encr = await crypto.EncryptWithPasswordAsync(testText, ENCRYPTION_PW);
                decr = await crypto.DecryptWithPasswordAsync(encr, ENCRYPTION_PW);

                Assert.Equal(testText, decr);

                encr = crypto.EncryptWithPassword(testText, ENCRYPTION_PW);
                decr = await crypto.DecryptWithPasswordAsync(encr, ENCRYPTION_PW);

                Assert.Equal(testText, decr);

                encr = await crypto.EncryptWithPasswordAsync(testText, ENCRYPTION_PW);
                decr = crypto.DecryptWithPassword(encr, ENCRYPTION_PW);

                Assert.Equal(testText, decr);
            }
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptStringUsingPw_NotIdenticalWithOriginal()
        {
            foreach (string testText in stringTests)
            {
                string encr;

                encr = crypto.EncryptWithPassword(testText, ENCRYPTION_PW);
                Assert.NotEqual(encr, testText);

                encr = await crypto.EncryptWithPasswordAsync(testText, ENCRYPTION_PW);
                Assert.NotEqual(encr, testText);
            }
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptStringUsingPw_DecryptStringUsingWrongPw_ReturnsNull()
        {
            foreach (string testText in stringTests)
            {
                string encr;
                string decr;

                encr = await crypto.EncryptWithPasswordAsync(testText, ENCRYPTION_PW);
                decr = await crypto.DecryptWithPasswordAsync(encr, WRONG_DECRYPTION_PW);

                Assert.NotEqual(testText, decr);
                Assert.Null(decr);

                encr = crypto.EncryptWithPassword(testText, ENCRYPTION_PW);
                decr = await crypto.DecryptWithPasswordAsync(encr, WRONG_DECRYPTION_PW);

                Assert.NotEqual(testText, decr);
                Assert.Null(decr);

                encr = await crypto.EncryptWithPasswordAsync(testText, ENCRYPTION_PW);
                decr = crypto.DecryptWithPassword(encr, WRONG_DECRYPTION_PW);

                Assert.NotEqual(testText, decr);
                Assert.Null(decr);
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public async Task SymmetricCryptography_EncryptStringUsingNullOrEmptyPw_ReturnsEmptyString(string pw)
        {
            foreach (string testText in stringTests)
            {
                string encr;

                encr = await crypto.EncryptWithPasswordAsync(testText, pw);
                Assert.Empty(encr);

                encr = crypto.EncryptWithPassword(testText, pw);
                Assert.Empty(encr);
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public async Task SymmetricCryptography_EncryptNullOrEmptyString_ReturnsEmptyString(string testData)
        {
            string encr;

            encr = await crypto.EncryptWithPasswordAsync(testData, ENCRYPTION_PW);
            Assert.Empty(encr);

            encr = crypto.EncryptWithPassword(testData, ENCRYPTION_PW);
            Assert.Empty(encr);
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptBytesUsingPw_DecryptBytesUsingPw_IdenticalAfterwards()
        {
            foreach (byte[] testBinary in binaryTests)
            {
                byte[] encr;
                byte[] decr;

                encr = await crypto.EncryptWithPasswordAsync(testBinary, ENCRYPTION_PW);
                decr = await crypto.DecryptWithPasswordAsync(encr, ENCRYPTION_PW);

                Assert.Equal(testBinary, decr);

                encr = crypto.EncryptWithPassword(testBinary, ENCRYPTION_PW);
                decr = await crypto.DecryptWithPasswordAsync(encr, ENCRYPTION_PW);

                Assert.Equal(testBinary, decr);

                encr = await crypto.EncryptWithPasswordAsync(testBinary, ENCRYPTION_PW);
                decr = crypto.DecryptWithPassword(encr, ENCRYPTION_PW);

                Assert.Equal(testBinary, decr);
            }
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptBytesUsingPw_NotIdenticalWithOriginal()
        {
            foreach (byte[] testBinary in binaryTests)
            {
                byte[] encr;

                encr = await crypto.EncryptWithPasswordAsync(testBinary, ENCRYPTION_PW);
                Assert.NotEqual(encr, testBinary);

                encr = crypto.EncryptWithPassword(testBinary, ENCRYPTION_PW);
                Assert.NotEqual(encr, testBinary);
            }
        }

        [Fact]
        public async Task SymmetricCryptography_EncryptBytesUsingPw_DecryptBytesUsingWrongPw_ReturnsNull()
        {
            foreach (byte[] testBinary in binaryTests)
            {
                byte[] encr;
                byte[] decr;

                encr = await crypto.EncryptWithPasswordAsync(testBinary, ENCRYPTION_PW);
                decr = await crypto.DecryptWithPasswordAsync(encr, WRONG_DECRYPTION_PW);

                Assert.NotEqual(encr, testBinary);
                Assert.Null(decr);

                encr = crypto.EncryptWithPassword(testBinary, ENCRYPTION_PW);
                decr = await crypto.DecryptWithPasswordAsync(encr, WRONG_DECRYPTION_PW);

                Assert.NotEqual(encr, testBinary);
                Assert.Null(decr);

                encr = await crypto.EncryptWithPasswordAsync(testBinary, ENCRYPTION_PW);
                decr = crypto.DecryptWithPassword(encr, WRONG_DECRYPTION_PW);

                Assert.NotEqual(encr, testBinary);
                Assert.Null(decr);

                encr = crypto.EncryptWithPassword(testBinary, ENCRYPTION_PW);
                decr = crypto.DecryptWithPassword(encr, WRONG_DECRYPTION_PW);

                Assert.NotEqual(encr, testBinary);
                Assert.Null(decr);
            }
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public async Task SymmetricCryptography_EncryptBytesUsingNullOrEmptyPw_ReturnsEmptyBytesArray(string pw)
        {
            foreach (byte[] testBinary in binaryTests)
            {
                byte[] encr;

                encr = await crypto.EncryptWithPasswordAsync(testBinary, pw);
                Assert.Empty(encr);

                encr = crypto.EncryptWithPassword(testBinary, pw);
                Assert.Empty(encr);
            }
        }

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        public async Task SymmetricCryptography_EncryptNullOrEmptyBytes_ReturnsEmptyBytesArray(byte[] d)
        {
            byte[] encr;

            encr = await crypto.EncryptWithPasswordAsync(d, ENCRYPTION_PW);
            Assert.Empty(encr);

            encr = crypto.EncryptWithPassword(d, ENCRYPTION_PW);
            Assert.Empty(encr);
        }

        [Fact]
        public async Task SymmetricCryptography_Encrypt_Decrypt_IdenticalAfterwards()
        {
            foreach (byte[] testBinary in binaryTests)
            {
                EncryptionResult encr;
                byte[] decr;

                encr = await crypto.EncryptAsync(testBinary);
                decr = await crypto.DecryptAsync(encr);
                Assert.Equal(decr, testBinary);

                encr = crypto.Encrypt(testBinary);
                decr = await crypto.DecryptAsync(encr);
                Assert.Equal(decr, testBinary);

                encr = await crypto.EncryptAsync(testBinary);
                decr = crypto.Decrypt(encr);
                Assert.Equal(decr, testBinary);

                encr = crypto.Encrypt(testBinary);
                decr = crypto.Decrypt(encr);
                Assert.Equal(decr, testBinary);
            }
        }

        [Fact]
        public async Task SymmetricCryptography_Encrypt_DifferentThanOriginal()
        {
            foreach (byte[] testBinary in binaryTests)
            {
                EncryptionResult encr;

                encr = await crypto.EncryptAsync(testBinary);
                Assert.NotEqual(encr.EncryptedData, testBinary);

                encr = crypto.Encrypt(testBinary);
                Assert.NotEqual(encr.EncryptedData, testBinary);
            }
        }

        [Fact]
        public async Task SymmetricCryptography_DecryptUsingNull_ReturnsEmptyBytesArray()
        {
            byte[] decr;

            decr = await crypto.DecryptAsync(null);
            Assert.Empty(decr);

            decr = crypto.Decrypt(null);
            Assert.Empty(decr);
        }

        [Fact]
        public async Task SymmetricCryptography_DecryptEmptyInstance_ReturnsEmptyByteArray()
        {
            byte[] decr;

            decr = await crypto.DecryptAsync(EncryptionResult.Empty);
            Assert.Empty(decr);

            decr = crypto.Decrypt(EncryptionResult.Empty);
            Assert.Empty(decr);
        }

        [Fact]
        public async Task SymmetricCryptography_Encrypt_DecryptUsingWrongData_ReturnsEmptyBytesArray()
        {
            foreach (byte[] testBinary in binaryTests)
            {
                EncryptionResult encr;
                byte[] decr;

                encr = await crypto.EncryptAsync(testBinary);
                decr = await crypto.DecryptAsync(new EncryptionResult()
                {
                    IV = new byte[] { 4, 5, 6 },
                    Key = new byte[] { 1, 2, 3 },
                    EncryptedData = new byte[] { 7, 8, 9 }
                });

                Assert.False(encr.IsEmpty());
                Assert.NotEqual(decr, testBinary);
                Assert.Null(decr);

                encr = crypto.Encrypt(testBinary);
                decr = crypto.Decrypt(new EncryptionResult()
                {
                    IV = new byte[] { 4, 5, 6 },
                    Key = new byte[] { 1, 2, 3 },
                    EncryptedData = new byte[] { 7, 8, 9 }
                });

                Assert.False(encr.IsEmpty());
                Assert.NotEqual(decr, testBinary);
                Assert.Null(decr);
            }
        }
    }
}