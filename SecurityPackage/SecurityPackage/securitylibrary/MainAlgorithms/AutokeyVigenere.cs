using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            string newKey = key;
            string cipherText = "";
            int diff = plainText.Length - key.Length;
            newKey += plainText.Substring(0, diff);
            for(int i = 0; i< plainText.Length; i++)
            {
                int character = (plainText[i] - 97 + newKey[i] - 97) % 26;
                cipherText += (char)(character + 97);
            }
            return cipherText;
        }
    }
}
