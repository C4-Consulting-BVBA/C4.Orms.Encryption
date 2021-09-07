using RestSharp;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace C4.Orms.Encryption
{
    public static class HttpHeaderExtensions
    {
        #region Methods

        #region Public

        public static bool IsEncrypted(this HttpHeader httpHeader) 
        {
            try
            {
                var temp = Convert.FromBase64String(httpHeader.Name);
                var decryptedPlaintext = Decrypt(temp);

                return true;
            }
            catch { }

            return false;
        }

        public static bool IsAcceptedEncryption(this HttpHeader httpHeader)
        {
            var name = Convert.FromBase64String(httpHeader.Name);
            var value = Convert.FromBase64String(httpHeader.Value);

            return name[name.Length - 1] == 0xFF && value[value.Length - 1] == 0xFF;
        }

        public static HttpHeader Encrypt(this HttpHeader httpHeader)
        {
            #region Name

            var plaintextBytes = Encoding.UTF8.GetBytes($"{httpHeader.Name}");
            var plaintext = Convert.ToBase64String(plaintextBytes);
            var key = new byte[32];

            RandomNumberGenerator.Fill(key);

            var (ciphertext, nonce, tag, result) = Encrypt(plaintext, key);

            httpHeader.Name = Convert.ToBase64String(result);

            #endregion

            #region value

            plaintextBytes = Encoding.UTF8.GetBytes($"{httpHeader.Value}");
            plaintext = Convert.ToBase64String(plaintextBytes);
            key = new byte[32];

            RandomNumberGenerator.Fill(key);

            (ciphertext, nonce, tag, result) = Encrypt(plaintext, key);

            httpHeader.Value = Convert.ToBase64String(result);

            #endregion

            return httpHeader;
        }

        public static List<HttpHeader> Encrypt(this List<HttpHeader> httpHeaders)
        {
            var returnValue = new List<HttpHeader>();

            httpHeaders.ForEach(x => 
            {
                returnValue.Add(Encrypt(x));
            });

            return returnValue;
        }

        public static HttpHeader Decrypt(this HttpHeader httpHeader)
        {
            #region Name

            var temp = Convert.FromBase64String(httpHeader.Name);
            var decryptedPlaintext = Decrypt(temp);

            temp = Convert.FromBase64String(decryptedPlaintext);
            httpHeader.Name = Encoding.UTF8.GetString(temp);

            #endregion

            #region Value

            temp = Convert.FromBase64String(httpHeader.Value);
            decryptedPlaintext = Decrypt(temp);

            temp = Convert.FromBase64String(decryptedPlaintext);
            httpHeader.Value = Encoding.UTF8.GetString(temp);

            #endregion

            return httpHeader;
        }

        public static List<HttpHeader> Decrypt(this List<HttpHeader> httpHeaders)
        {
            var returnValue = new List<HttpHeader>();

            httpHeaders.ForEach(x =>
            {
                returnValue.Add(Decrypt(x));
            });

            return returnValue;
        }

        #endregion

        #region Private

        private static (byte[] ciphertext, byte[] nonce, byte[] tag, byte[] result) Encrypt(string plaintext, byte[] key)
        {
            using (var aes = new AesGcm(key))
            {
                var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
                RandomNumberGenerator.Fill(nonce);

                var tag = new byte[AesGcm.TagByteSizes.MaxSize];
                var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                var ciphertext = new byte[plaintextBytes.Length];
                var result = new byte[ciphertext.Length + nonce.Length + tag.Length + key.Length + 1];

                aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

                ciphertext.CopyTo(result, 0);
                nonce.CopyTo(result, ciphertext.Length);
                tag.CopyTo(result, ciphertext.Length + nonce.Length);
                key.CopyTo(result, ciphertext.Length + nonce.Length + tag.Length);

                result[result.Length - 1] = 0xFF;

                return (ciphertext, nonce, tag, result);
            }
        }

        private static string Decrypt(byte[] encryptedHeader)
        {
            var isValidEncryption = encryptedHeader[encryptedHeader.Length-1] == 0xFF;

            if (!isValidEncryption) 
            {
                return string.Empty;
            }

            var temp = new byte[encryptedHeader.Length - 1];

            Buffer.BlockCopy(encryptedHeader, 0, temp, 0, encryptedHeader.Length - 1);

            var key = new byte[32];
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            var ciphertext = new byte[temp.Length - nonce.Length - tag.Length - key.Length];
            var sourceOffset = 0;

            Buffer.BlockCopy(temp, sourceOffset, ciphertext, 0, temp.Length - nonce.Length - tag.Length - key.Length);

            sourceOffset += (temp.Length - nonce.Length - tag.Length - key.Length);

            Buffer.BlockCopy(temp, sourceOffset, nonce, 0, temp.Length - ciphertext.Length - tag.Length - key.Length);

            sourceOffset += (temp.Length - ciphertext.Length - tag.Length - key.Length);

            Buffer.BlockCopy(temp, sourceOffset, tag, 0, temp.Length - ciphertext.Length - nonce.Length - key.Length);

            sourceOffset += (temp.Length - ciphertext.Length - nonce.Length - key.Length);

            Buffer.BlockCopy(temp, sourceOffset, key, 0, temp.Length - ciphertext.Length - nonce.Length - tag.Length);

            using (var aes = new AesGcm(key))
            {
                var plaintextBytes = new byte[ciphertext.Length];

                aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

                return Encoding.UTF8.GetString(plaintextBytes);
            }
        }

        #endregion

        #endregion
    }
}