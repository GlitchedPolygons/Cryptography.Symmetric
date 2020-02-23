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

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace GlitchedPolygons.Services.Cryptography.Symmetric
{
    /// <summary>
    /// Service interface implementation for symmetrically encrypting/decrypting data (raw <c>byte[]</c> arrays) using <see cref="AesManaged"/>.<para> </para>
    /// Please keep in mind that the data you encrypt with <see cref="EncryptWithPassword(byte[],string)"/> can only be decrypted using the same password and the corresponding mirror method <see cref="DecryptWithPassword(byte[],string)"/>.<para> </para>
    /// Likewise, data encrypted using <see cref="Encrypt"/> can only be decrypted again using <see cref="Decrypt"/> respectively.
    /// Implements the <see cref="ISymmetricCryptography" /> <c>interface</c>.
    /// </summary>
    public class SymmetricCryptography : ISymmetricCryptography
    {
        private const int RFC_ITERATIONS = 16384;

        public EncryptionResult Encrypt(byte[] data)
        {
            if (data is null || data.Length == 0)
            {
                return EncryptionResult.Empty;
            }

            using var aes = new AesManaged
            {
                KeySize = 256, 
                Mode = CipherMode.CBC, 
                Padding = PaddingMode.PKCS7
            };

            aes.GenerateIV();
            aes.GenerateKey();

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            
            return new EncryptionResult
            {
                IV = aes.IV,
                Key = aes.Key,
                EncryptedData = encryptor.TransformFinalBlock(data, 0, data.Length)
            };
        }

        public byte[] EncryptWithPassword(byte[] data, string password)
        {
            if (data is null || data.Length == 0 || string.IsNullOrEmpty(password))
            {
                return Array.Empty<byte>();
            }

            byte[] salt = new byte[32];
            
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            using var aes = new AesManaged();
            using var rfc = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);

            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            aes.IV = rfc.GetBytes(16);
            aes.Key = rfc.GetBytes(32);

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            
            return salt.Concat(encryptor.TransformFinalBlock(data, 0, data.Length)).ToArray();
        }
        
        public string EncryptWithPassword(string data, string password)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(password))
            {
                return string.Empty;
            }

            try
            {
                return Convert.ToBase64String(EncryptWithPassword(Encoding.UTF8.GetBytes(data), password));
            }
            catch (Exception)
            {
                return null;
            }
        }
        
        public async Task<EncryptionResult> EncryptAsync(byte[] data)
        {
            int dataLength = data?.Length ?? 0;
            
            if (dataLength == 0)
            {
                return EncryptionResult.Empty;
            }

            using var aes = new AesManaged
            {
                KeySize = 256,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            aes.GenerateIV();
            aes.GenerateKey();
            
            await using var output = new MemoryStream(dataLength);
            await using var cryptoStream = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
            
            await cryptoStream.WriteAsync(data, 0, dataLength);

            return new EncryptionResult
            {
                IV = aes.IV,
                Key = aes.Key,
                EncryptedData = output.ToArray()
            };
        }

        public async Task<byte[]> EncryptWithPasswordAsync(byte[] data, string password)
        {
            int dataLength = data?.Length ?? 0;
            
            if (dataLength == 0 || string.IsNullOrEmpty(password))
            {
                return Array.Empty<byte>();
            }
            
            byte[] salt = new byte[32];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(salt);
            }

            using var aes = new AesManaged();
            using var rfc = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);
            
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
                        
            aes.IV = rfc.GetBytes(16);
            aes.Key = rfc.GetBytes(32);
            
            await using var output = new MemoryStream(dataLength);
            await using var cryptoStream = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write);

            await output.WriteAsync(salt, 0, salt.Length);
            await cryptoStream.WriteAsync(data, 0, dataLength);

            return output.ToArray();
        }

        public async Task<string> EncryptWithPasswordAsync(string data, string password)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(password))
            {
                return string.Empty;
            }

            try
            {
                return Convert.ToBase64String(await EncryptWithPasswordAsync(Encoding.UTF8.GetBytes(data), password));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public byte[] Decrypt(EncryptionResult encryptionResult)
        {
            if (encryptionResult?.EncryptedData is null || encryptionResult.EncryptedData.Length == 0)
            {
                return Array.Empty<byte>();
            }

            byte[] result;
            AesManaged aes = null;
            ICryptoTransform decryptor = null;

            try
            {
                aes = new AesManaged
                {
                    KeySize = 256,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7,
                    IV = encryptionResult.IV,
                    Key = encryptionResult.Key
                };

                decryptor = aes.CreateDecryptor();

                result = decryptor.TransformFinalBlock(encryptionResult.EncryptedData, 0, encryptionResult.EncryptedData.Length);
            }
            catch
            {
                result = null;
            }
            finally
            {
                aes?.Dispose();
                decryptor?.Dispose();
            }
            
            return result;
        }
        
        public byte[] DecryptWithPassword(byte[] encryptedBytes, string password)
        {
            if (encryptedBytes is null || encryptedBytes.Length <= 32 || string.IsNullOrEmpty(password))
            {
                return Array.Empty<byte>();
            }

            byte[] decryptedBytes;
            byte[] salt = new byte[32];
            byte[] encr = new byte[encryptedBytes.Length - 32];
            
            for (int i = 0; i < salt.Length; i++)
            {
                salt[i] = encryptedBytes[i];
            }

            for (int i = 0; i < encr.Length; i++)
            {
                encr[i] = encryptedBytes[i + 32];
            }

            var aes = new AesManaged();
            var rfc = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);

            try
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                aes.IV = rfc.GetBytes(16);
                aes.Key = rfc.GetBytes(32);

                using ICryptoTransform decryptor = aes.CreateDecryptor();
                
                decryptedBytes = decryptor.TransformFinalBlock(encr, 0, encr.Length);
            }
            catch (Exception)
            {
                decryptedBytes = null;
            }
            finally
            {
                aes.Dispose();
                rfc.Dispose();
            }

            return decryptedBytes;
        }
        
        public string DecryptWithPassword(string data, string password)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(password))
            {
                return string.Empty;
            }

            try
            {
                return Encoding.UTF8.GetString(DecryptWithPassword(Convert.FromBase64String(data), password));
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task<byte[]> DecryptAsync(EncryptionResult encryptionResult)
        {
            throw new NotImplementedException();
        }

        public async Task<byte[]> DecryptWithPasswordAsync(byte[] encryptedBytes, string password)
        {
            throw new NotImplementedException();
        }

        public async Task<string> DecryptWithPasswordAsync(string data, string password)
        {
            throw new NotImplementedException();
        }
    }
}