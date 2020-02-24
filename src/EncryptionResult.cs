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

namespace GlitchedPolygons.Services.Cryptography.Symmetric
{
    /// <summary>
    /// The result of encrypting some data using the <see cref="SymmetricCryptography.Encrypt"/> method.
    /// Contains the encrypted bytes and the key + initialization vector used for the encryption (you need those for decryption).
    /// Implements the <see cref="System.IDisposable" />
    /// </summary>
    /// <seealso cref="System.IDisposable" />
    public class EncryptionResult : IDisposable
    {
        /// <summary>
        /// The initialization vector.
        /// </summary>
        public byte[] IV { get; set; }

        /// <summary>
        /// The encryption key.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// The encrypted data bytes.
        /// </summary>
        public byte[] EncryptedData { get; set; }

        /// <summary>
        /// Overwrites the <see cref="Key"/> and <see cref="IV"/> bytes with zeros.
        /// </summary>
        public void Dispose()
        {
            if (IV != null)
            {
                for (int i = 0; i < IV.Length; i++)
                {
                    IV[i] = 0;
                }
            }

            if (Key != null)
            {
                for (int i = 0; i < Key.Length; i++)
                {
                    Key[i] = 0;
                }
            }
        }

        /// <summary>
        /// Checks whether this <see cref="EncryptionResult"/> instance is empty (all its fields <c>null</c>) or not.
        /// </summary>
        /// <returns>Whether this <see cref="EncryptionResult"/> instance is empty (all its fields <c>null</c>) or not.</returns>
        public bool IsEmpty() => IV is null && Key is null && EncryptedData is null;

        /// <summary>
        /// Gets a new empty <see cref="EncryptionResult"/> instance.
        /// </summary>
        public static EncryptionResult Empty => new EncryptionResult { Key = null, IV = null, EncryptedData = null };
    }
}