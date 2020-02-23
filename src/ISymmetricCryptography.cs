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
using System.Threading.Tasks;

namespace GlitchedPolygons.Services.Cryptography.Symmetric
{
    /// <summary>
    /// Service interface for symmetrically encrypting/decrypting data (raw <c>byte[]</c> arrays).<para> </para>
    /// Please keep in mind that the data you encrypt with <see cref="EncryptWithPassword(byte[],string)"/> can only be decrypted using the same password and the corresponding mirror method <see cref="DecryptWithPassword(byte[],string)"/>.<para> </para>
    /// Likewise, data encrypted using <see cref="Encrypt"/> can only be decrypted again using <see cref="Decrypt"/> respectively.
    /// </summary>
    public interface ISymmetricCryptography
    {
        /// <summary>
        /// Encrypts the specified data using a randomly generated key and initialization vector.<para> </para>
        /// Returns an <see cref="EncryptionResult"/> containing the encrypted <c>byte[]</c> array + the used encryption key and iv.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns><see cref="EncryptionResult"/> containing the encrypted <c>byte[]</c> array + the used encryption key and iv.</returns>
        EncryptionResult Encrypt(byte[] data);

        /// <summary>
        /// Encrypts data using a password.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password used to derive the AES key.</param>
        /// <returns>The encrypted data bytes.</returns>
        byte[] EncryptWithPassword(byte[] data, string password);
        
        /// <summary>
        /// Encrypts data using a password.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password used to derive the AES key.</param>
        /// <returns>The encrypted data.</returns>
        string EncryptWithPassword(string data, string password);
        
        /// <summary>
        /// Encrypts the specified data asynchronously using a randomly generated key and initialization vector.<para> </para>
        /// Returns an <see cref="EncryptionResult"/> containing the encrypted <c>byte[]</c> array + the used encryption key and iv.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <returns><see cref="EncryptionResult"/> containing the encrypted <c>byte[]</c> array + the used encryption key and iv.</returns>
        Task<EncryptionResult> EncryptAsync(byte[] data);
        
        /// <summary>
        /// Encrypts data asynchronously using a password.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password used to derive the AES key.</param>
        /// <returns>The encrypted data bytes.</returns>
        Task<byte[]> EncryptWithPasswordAsync(byte[] data, string password);

        /// <summary>
        /// Encrypts data asynchronously using a password.
        /// </summary>
        /// <param name="data">The data to encrypt asynchronously.</param>
        /// <param name="password">The password used to derive the AES key.</param>
        /// <returns>The encrypted data.</returns>
        Task<string> EncryptWithPasswordAsync(string data, string password);

        /// <summary>
        /// Decrypts the specified <see cref="EncryptionResult"/> that was obtained using <see cref="ISymmetricCryptography.Encrypt(byte[])"/>.
        /// </summary>
        /// <param name="encryptionResult">The <see cref="EncryptionResult"/> that was obtained using <see cref="ISymmetricCryptography.Encrypt(byte[])"/>.</param>
        /// <returns>Decrypted <c>byte[]</c> or <c>null</c> if decryption failed.</returns>
        byte[] Decrypt(EncryptionResult encryptionResult);
        
        /// <summary>
        /// Decrypts data that was encrypted using <see cref="EncryptWithPassword(byte[],string)"/>.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted data.</param>
        /// <param name="password">The password that was used to encrypt the data.</param>
        /// <returns>The decrypted <c>byte[]</c> array.</returns>
        byte[] DecryptWithPassword(byte[] encryptedBytes, string password);

        /// <summary>
        /// Decrypts a string that was encrypted using <see cref="EncryptWithPassword(string,string)"/>.
        /// </summary>
        /// <param name="data">The encrypted data.</param>
        /// <param name="password">The password that was used to encrypt the data.</param>
        /// <returns>The decrypted data.</returns>
        string DecryptWithPassword(string data, string password);

        /// <summary>
        /// Asynchronously decrypts the specified <see cref="EncryptionResult"/> that was obtained using <see cref="ISymmetricCryptography.Encrypt(byte[])"/>.
        /// </summary>
        /// <param name="encryptionResult">The <see cref="EncryptionResult"/> that was obtained using <see cref="ISymmetricCryptography.Encrypt(byte[])"/>.</param>
        /// <returns>Decrypted <c>byte[]</c> or <c>null</c> if decryption failed.</returns>
        Task<byte[]> DecryptAsync(EncryptionResult encryptionResult);
        
        /// <summary>
        /// Asynchronously decrypts data that was encrypted using <see cref="EncryptWithPassword(byte[],string)"/>.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted data.</param>
        /// <param name="password">The password that was used to encrypt the data.</param>
        /// <returns>The decrypted <c>byte[]</c> array.</returns>
        Task<byte[]> DecryptWithPasswordAsync(byte[] encryptedBytes, string password);
        
        /// <summary>
        /// Asynchronously decrypts a string that was encrypted using <see cref="EncryptWithPassword(string,string)"/>.
        /// </summary>
        /// <param name="data">The encrypted data.</param>
        /// <param name="password">The password that was used to encrypt the data.</param>
        /// <returns>The decrypted string.</returns>
        Task<string> DecryptWithPasswordAsync(string data, string password);
    }
}