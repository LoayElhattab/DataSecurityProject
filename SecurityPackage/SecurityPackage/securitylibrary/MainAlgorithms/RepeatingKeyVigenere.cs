using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string key = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int character = ((cipherText[i] - 97) - (plainText[i] - 97) + 26) % 26;
                key += (char)(character + 97);
                if (Encrypt(plainText, key) == cipherText)
                    break;
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            string keyStream = "";
            string plainText = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                keyStream += key[i % key.Length];
                int character = ((cipherText[i] - 97) - (keyStream[i] - 97) + 26) % 26;
                plainText += (char)(character + 97);
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string keyStream = "";
            string cipherText = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                keyStream += key[i % key.Length];
                int character = (plainText[i] - 97 + keyStream[i] - 97) % 26;
                cipherText += (char)(character + 97);
            }
            return cipherText;
        }
    }
}