using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using RestSharp;

namespace C4.Orms.Encryption
{
    class Program
    {
        public static void Main()
        {
            var plaintextBytes = Encoding.UTF8.GetBytes("Predicate:UserModel|true|Equal|value|true");
            var plaintext = Convert.ToBase64String(plaintextBytes);
            var key = new byte[32];

            RandomNumberGenerator.Fill(key);

            var (ciphertext, nonce, tag, result) = Encrypt(plaintext, key);

            var x1 = Convert.ToBase64String(ciphertext);
            var x2 = Convert.ToBase64String(nonce);
            var x3 = Convert.ToBase64String(tag);
            var x4 = Convert.ToBase64String(key);
            var x5 = Convert.ToBase64String(result);

            var decryptedPlaintext = Decrypt(result);

            if (decryptedPlaintext.Equals(plaintext))
            {
                var temp = Convert.FromBase64String(decryptedPlaintext);
                var decryptedHeader = Encoding.UTF8.GetString(temp);

                Console.WriteLine("Decryption succesful!");
            }
            else 
            {
                Console.WriteLine("Error!");
            }
        }

        private static (byte[] ciphertext, byte[] nonce, byte[] tag, byte[] result) Encrypt(string plaintext, byte[] key)
        {
            using (var aes = new AesGcm(key))
            {
                var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
                RandomNumberGenerator.Fill(nonce);

                var tag = new byte[AesGcm.TagByteSizes.MaxSize];
                var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                var ciphertext = new byte[plaintextBytes.Length];
                var result = new byte[ciphertext.Length + nonce.Length + tag.Length + key.Length];

                aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

                ciphertext.CopyTo(result, 0);
                nonce.CopyTo(result, ciphertext.Length);
                tag.CopyTo(result, ciphertext.Length + nonce.Length);
                key.CopyTo(result, ciphertext.Length + nonce.Length + tag.Length);

                return (ciphertext, nonce, tag, result);
            }
        }

        private static string Decrypt(byte[] encryptedHeader)
        {
            var key = new byte[32];
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            var ciphertext = new byte[encryptedHeader.Length - nonce.Length - tag.Length - key.Length];
            var sourceOffset = 0;

            Buffer.BlockCopy(encryptedHeader, sourceOffset, ciphertext, 0, encryptedHeader.Length - nonce.Length - tag.Length - key.Length);

            sourceOffset += (encryptedHeader.Length - nonce.Length - tag.Length - key.Length);

            Buffer.BlockCopy(encryptedHeader, sourceOffset, nonce, 0, encryptedHeader.Length - ciphertext.Length - tag.Length - key.Length);

            sourceOffset += (encryptedHeader.Length - ciphertext.Length - tag.Length - key.Length);

            Buffer.BlockCopy(encryptedHeader, sourceOffset, tag, 0, encryptedHeader.Length - ciphertext.Length - nonce.Length - key.Length);

            sourceOffset += (encryptedHeader.Length - ciphertext.Length - nonce.Length - key.Length);

            Buffer.BlockCopy(encryptedHeader, sourceOffset, key, 0, encryptedHeader.Length - ciphertext.Length - nonce.Length - tag.Length);

            using (var aes = new AesGcm(key))
            {
                var plaintextBytes = new byte[ciphertext.Length];

                aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

                return Encoding.UTF8.GetString(plaintextBytes);
            }
        }

        private List<HttpHeader> EncryptHeaders(List<HttpHeader> headers)
        {
            var returnValue = new List<HttpHeader>();

            headers.ForEach(x =>
            {
                var name = string.Empty;
                var value = string.Empty;

                #region Name

                var plaintextBytes = Encoding.UTF8.GetBytes($"{x.Name}");
                var plaintext = Convert.ToBase64String(plaintextBytes);
                var key = new byte[32];

                RandomNumberGenerator.Fill(key);

                var (ciphertext, nonce, tag, result) = Encrypt(plaintext, key);

                name = Convert.ToBase64String(result);

                #endregion

                #region value

                plaintextBytes = Encoding.UTF8.GetBytes($"{x.Value}");
                plaintext = Convert.ToBase64String(plaintextBytes);
                key = new byte[32];

                RandomNumberGenerator.Fill(key);

                (ciphertext, nonce, tag, result) = Encrypt(plaintext, key);

                value = Convert.ToBase64String(result);

                #endregion

                returnValue.Add(new HttpHeader(name, value));
            });

            return returnValue;
        }

        private List<HttpHeader> DecryptHeaders(List<HttpHeader> headers)
        {
            var returnValue = new List<HttpHeader>();

            headers.ForEach(x =>
            {
                var name = string.Empty;
                var value = string.Empty;

                #region Name

                var temp = Convert.FromBase64String(x.Name);
                var decryptedPlaintext = Decrypt(temp);

                temp = Convert.FromBase64String(decryptedPlaintext);
                name = Encoding.UTF8.GetString(temp);

                #endregion

                #region Value

                temp = Convert.FromBase64String(x.Value);
                decryptedPlaintext = Decrypt(temp);

                temp = Convert.FromBase64String(decryptedPlaintext);
                value = Encoding.UTF8.GetString(temp);

                #endregion

                returnValue.Add(new HttpHeader(name, value));
            });

            return returnValue;
        }
    }
}
