#nullable disable

using System.Security.Cryptography;
using System.Text;

namespace EncryptDecrypt
{
    internal class Encryption_Works_With_CSharp_TypeScript
    {
        public static string _securityKey = "m_0V=5RoO+v8iG7?";

        public static string DecryptStringAES(string cipherText)
        {
            var keybytes = Encoding.UTF8.GetBytes(_securityKey);
            var iv = Encoding.UTF8.GetBytes(_securityKey);

            var encrypted = Convert.FromBase64String(cipherText);
            var decriptedFromJavascript = DecryptStringFromBytes(encrypted, keybytes, iv);
            return decriptedFromJavascript;
        }

        private static string DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
        {
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }

            string plaintext = null;
            using (var rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.Mode = CipherMode.CBC;
                rijndaelManaged.Padding = PaddingMode.PKCS7;
                rijndaelManaged.FeedbackSize = 128;
                rijndaelManaged.Key = key;
                rijndaelManaged.IV = iv;

                var decryptor = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV);
                try
                {
                    using (var memoryStream = new MemoryStream(cipherText))
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var streamReader = new StreamReader(cryptoStream))
                            {
                                plaintext = streamReader.ReadToEnd();
                            }
                        }
                    }
                }
                catch
                {
                    plaintext = "keyError";
                }
            }
            return plaintext;
        }

        public static string EncryptStringAES(string plainText)
        {
            var keybytes = Encoding.UTF8.GetBytes(_securityKey);
            var iv = Encoding.UTF8.GetBytes(_securityKey);

            var encryoFromJavascript = EncryptStringToBytes(plainText, keybytes, iv);
            return Convert.ToBase64String(encryoFromJavascript);
        }

        private static byte[] EncryptStringToBytes(string plainText, byte[] key, byte[] iv)
        {
            if (plainText == null || plainText.Length <= 0)
            {
                throw new ArgumentNullException("plainText");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }

            byte[] encrypted;
            using (var rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.Mode = CipherMode.CBC;
                rijndaelManaged.Padding = PaddingMode.PKCS7;
                rijndaelManaged.FeedbackSize = 128;
                rijndaelManaged.Key = key;
                rijndaelManaged.IV = iv;
                var encryptor = rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV);
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(plainText);
                        }
                        encrypted = memoryStream.ToArray();
                    }
                }
            }
            return encrypted;
        }

        ////Inside imports of your TypeScript file include
        //import* as CryptoJS from 'crypto-js';

        //// Declare this key and iv values in declaration
        //private key = CryptoJS.enc.Utf8.parse('4512631236589784');
        //private iv = CryptoJS.enc.Utf8.parse('4512631236589784');

        //// Methods for the encrypt and decrypt Using AES
        //encryptUsingAES256()
        //{
        //    var encrypted = CryptoJS.AES.encrypt(CryptoJS.enc.Utf8.parse(JSON.stringify("Your Json Object data or string")), this.key, {
        //        keySize: 128 / 8,
        //        iv: this.iv,
        //        mode: CryptoJS.mode.CBC,
        //        padding: CryptoJS.pad.Pkcs7
        //    });
        //    console.log('Encrypted :' + encrypted);
        //    this.decryptUsingAES256(encrypted);
        //    return encrypted;
        //}

        //decryptUsingAES256(decString)
        //{
        //    var decrypted = CryptoJS.AES.decrypt(decString, this.key, {
        //        keySize: 128 / 8,
        //        iv: this.iv,
        //        mode: CryptoJS.mode.CBC,
        //        padding: CryptoJS.pad.Pkcs7
        //    });
        //    console.log('Decrypted : ' + decrypted);
        //    console.log('utf8 = ' + decrypted.toString(CryptoJS.enc.Utf8));
        //}
    }
}
