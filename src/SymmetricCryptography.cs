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

using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

// ReSharper disable AssignNullToNotNullAttribute
// ReSharper disable PossibleNullReferenceException

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

        /// <summary>
        /// Encrypts the specified data using a randomly generated key and initialization vector.<para> </para>
        /// Returns an <see cref="EncryptionResult"/> containing the encrypted <c>byte[]</c> array + the used encryption key and iv.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns><see cref="EncryptionResult"/> containing the encrypted <c>byte[]</c> array + the used encryption key and iv.</returns>
        public EncryptionResult Encrypt(byte[] data)
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

            using ICryptoTransform encryptor = aes.CreateEncryptor();
            
            return new EncryptionResult
            {
                IV = aes.IV,
                Key = aes.Key,
                EncryptedData = encryptor.TransformFinalBlock(data, 0, dataLength)
            };
        }

        /// <summary>
        /// Encrypts data using a password.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password used to derive the AES key.</param>
        /// <returns>The encrypted data bytes.</returns>
        public byte[] EncryptWithPassword(byte[] data, string password)
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

            using var output = new MemoryStream(dataLength);
            using ICryptoTransform encryptor = aes.CreateEncryptor();
            
            output.Write(salt, 0, salt.Length);
            output.Write(encryptor.TransformFinalBlock(data, 0, dataLength));
            output.Flush();
            
            return output.ToArray();
        }

        /// <summary>
        /// Encrypts data using a password.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password used to derive the AES key.</param>
        /// <returns>The encrypted data; <c>null</c> if encryption failed; <c>string.Empty</c> if the passed parameters were invalid.</returns>
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
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Encrypts the specified data asynchronously using a randomly generated key and initialization vector.<para> </para>
        /// Returns an <see cref="EncryptionResult"/> containing the encrypted <c>byte[]</c> array + the used encryption key and iv.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns><see cref="EncryptionResult"/> containing the encrypted <c>byte[]</c> array + the used encryption key and iv.</returns>
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
            
            using ICryptoTransform encryptor = aes.CreateEncryptor();
            
            await using var output = new MemoryStream(dataLength);
            await using var cryptoStream = new CryptoStream(output, encryptor, CryptoStreamMode.Write);
            
            await cryptoStream.WriteAsync(data, 0, dataLength).ConfigureAwait(false);
            
            cryptoStream.FlushFinalBlock();
            
            return new EncryptionResult
            {
                IV = aes.IV,
                Key = aes.Key,
                EncryptedData = output.ToArray()
            };
        }

        /// <summary>
        /// Encrypts data asynchronously using a password.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password used to derive the AES key.</param>
        /// <returns>The encrypted data bytes.</returns>
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
            
            using ICryptoTransform encryptor = aes.CreateEncryptor();
            
            await using var output = new MemoryStream(dataLength);
            await using var cryptoStream = new CryptoStream(output, encryptor, CryptoStreamMode.Write);

            await output.WriteAsync(salt, 0, salt.Length).ConfigureAwait(false);
            await cryptoStream.WriteAsync(data, 0, dataLength).ConfigureAwait(false);
            
            cryptoStream.FlushFinalBlock();
            
            return output.ToArray();
        }

        /// <summary>
        /// Encrypts data asynchronously using a password.
        /// </summary>
        /// <param name="data">The data to encrypt asynchronously.</param>
        /// <param name="password">The password used to derive the AES key.</param>
        /// <returns>The encrypted data.</returns>
        public async Task<string> EncryptWithPasswordAsync(string data, string password)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(password))
            {
                return string.Empty;
            }

            try
            {
                byte[] utf8 = Encoding.UTF8.GetBytes(data);
                byte[] encryptedBytes = await EncryptWithPasswordAsync(utf8, password).ConfigureAwait(false);
                return Convert.ToBase64String(encryptedBytes);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Decrypts the specified <see cref="EncryptionResult"/> that was obtained using <see cref="ISymmetricCryptography.Encrypt(byte[])"/>.
        /// </summary>
        /// <param name="encryptionResult">The <see cref="EncryptionResult"/> that was obtained using <see cref="ISymmetricCryptography.Encrypt(byte[])"/>.</param>
        /// <returns>Decrypted <c>byte[]</c> array or <c>null</c> if decryption failed.</returns>
        public byte[] Decrypt(EncryptionResult encryptionResult)
        {
            int encryptedBytesLength = encryptionResult?.EncryptedData?.Length ?? 0;
            
            if (encryptedBytesLength == 0)
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

                result = decryptor.TransformFinalBlock(encryptionResult.EncryptedData, 0, encryptedBytesLength);
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

        /// <summary>
        /// Decrypts data that was encrypted using <see cref="ISymmetricCryptography.EncryptWithPassword(byte[],string)"/>.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted data.</param>
        /// <param name="password">The password that was used to encrypt the data.</param>
        /// <returns>The decrypted <c>byte[]</c> array.</returns>
        public byte[] DecryptWithPassword(byte[] encryptedBytes, string password)
        {
            int encryptedBytesLength = encryptedBytes?.Length ?? 0;
            
            if (encryptedBytesLength <= 32 || string.IsNullOrEmpty(password))
            {
                return Array.Empty<byte>();
            }

            byte[] decryptedBytes;
            byte[] salt = new byte[32];
            
            for (int i = 0; i < 32; i++)
            {
                salt[i] = encryptedBytes[i];
            }

            AesManaged aes = null;
            Rfc2898DeriveBytes rfc = null;

            try
            {
                rfc = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);
                
                aes = new AesManaged
                {
                    KeySize = 256,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7,
                    IV = rfc.GetBytes(16),
                    Key = rfc.GetBytes(32)
                };

                using ICryptoTransform decryptor = aes.CreateDecryptor();
                
                decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 32, encryptedBytesLength - 32);
            }
            catch
            {
                decryptedBytes = null;
            }
            finally
            {
                aes?.Dispose();
                rfc?.Dispose();
            }

            return decryptedBytes;
        }

        /// <summary>
        /// Decrypts a string that was encrypted using <see cref="ISymmetricCryptography.EncryptWithPassword(string,string)"/>.
        /// </summary>
        /// <param name="data">The encrypted data.</param>
        /// <param name="password">The password that was used to encrypt the data.</param>
        /// <returns>The decrypted data.</returns>
        public string DecryptWithPassword(string data, string password)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(password))
            {
                return string.Empty;
            }
            
            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(data);
                byte[] decryptedBytes = DecryptWithPassword(encryptedBytes, password);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Asynchronously decrypts the specified <see cref="EncryptionResult"/> that was obtained using <see cref="ISymmetricCryptography.EncryptAsync(byte[])"/>.
        /// </summary>
        /// <param name="encryptionResult">The <see cref="EncryptionResult"/> that was obtained using <see cref="ISymmetricCryptography.EncryptAsync(byte[])"/>.</param>
        /// <returns>Decrypted <c>byte[]</c> or <c>null</c> if decryption failed.</returns>
        public async Task<byte[]> DecryptAsync(EncryptionResult encryptionResult)
        {
            int encryptedBytesLength = encryptionResult?.EncryptedData?.Length ?? 0;
            
            if (encryptedBytesLength == 0)
            {
                return Array.Empty<byte>();
            }

            byte[] result;
            await using var output = new MemoryStream(encryptedBytesLength);
            await using var input = new MemoryStream(encryptionResult.EncryptedData);
            
            try
            {
                using var aes = new AesManaged
                {
                    KeySize = 256,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7,
                    IV = encryptionResult.IV,
                    Key = encryptionResult.Key
                };

                using ICryptoTransform decryptor = aes.CreateDecryptor();
                
                await using var cryptoStream = new CryptoStream(input, decryptor, CryptoStreamMode.Read);
                await cryptoStream.CopyToAsync(output).ConfigureAwait(false);
                await cryptoStream.FlushAsync();
                
                result = output.ToArray();
            }
            catch
            {
                result = null;
            }
            
            return result;
        }

        /// <summary>
        /// Asynchronously decrypts data that was encrypted using <see cref="ISymmetricCryptography.EncryptWithPasswordAsync(byte[],string)"/>.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted data.</param>
        /// <param name="password">The password that was used to encrypt the data.</param>
        /// <returns>The decrypted <c>byte[]</c> array.</returns>
        public async Task<byte[]> DecryptWithPasswordAsync(byte[] encryptedBytes, string password)
        {
            int encryptedBytesLength = encryptedBytes?.Length ?? 0;
            
            if (encryptedBytesLength <= 32 || string.IsNullOrEmpty(password))
            {
                return Array.Empty<byte>();
            }

            byte[] salt = new byte[32];
            
            for (int i = 0; i < 32; i++)
            {
                salt[i] = encryptedBytes[i];
            }
            
            byte[] result;

            await using var output = new MemoryStream(encryptedBytesLength);
            await using var input = new MemoryStream(encryptedBytes, 32, encryptedBytesLength - 32);
            
            try
            {
                using var rfc = new Rfc2898DeriveBytes(password, salt, RFC_ITERATIONS);
                
                using var aes = new AesManaged
                {
                    KeySize = 256,
                    Mode = CipherMode.CBC,
                    Padding = PaddingMode.PKCS7,
                    IV = rfc.GetBytes(16),
                    Key = rfc.GetBytes(32)
                };
                
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                
                await using var cryptoStream = new CryptoStream(input, decryptor, CryptoStreamMode.Read);
                await cryptoStream.CopyToAsync(output).ConfigureAwait(false);
                await cryptoStream.FlushAsync().ConfigureAwait(false);
                
                result = output.ToArray();
            }
            catch
            {
                result = null;
            }

            return result;
        }

        /// <summary>
        /// Asynchronously decrypts a string that was encrypted using <see cref="ISymmetricCryptography.EncryptWithPassword(string,string)"/>.
        /// </summary>
        /// <param name="data">The encrypted data string.</param>
        /// <param name="password">The password that was used to encrypt the data.</param>
        /// <returns>The decrypted string; <c>string.Empty</c> if you passed invalid arguments; <c>null</c> if decryption failed.</returns>
        public async Task<string> DecryptWithPasswordAsync(string data, string password)
        {
            if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(password))
            {
                return string.Empty;
            }
            
            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(data);
                byte[] decryptedBytes = await DecryptWithPasswordAsync(encryptedBytes, password).ConfigureAwait(false);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch
            {
                return null;
            }
        }
    }
}