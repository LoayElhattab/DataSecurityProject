using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            string key1 = key[0];
            string key2 = key[1];
            string firstDecryption = des.Decrypt(cipherText, key1);
            string intermediateEncryption = des.Encrypt(firstDecryption, key2);
            string finalPlainText = des.Decrypt(intermediateEncryption, key1);

            return finalPlainText;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES des = new DES();
            string key1 = key[0];
            string key2 = key[1];
            string firstEncryption = des.Encrypt(plainText, key1);
            string intermediateDecryption = des.Decrypt(firstEncryption, key2);
            string finalCipherText = des.Encrypt(intermediateDecryption, key1);
            return finalCipherText;
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}
