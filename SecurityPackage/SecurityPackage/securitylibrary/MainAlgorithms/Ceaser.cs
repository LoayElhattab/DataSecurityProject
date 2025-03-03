using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipher = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int x = (int)(plainText[i] - 'a' + key) % 26;

                cipher += (char)(x + 'a');

            }
            return cipher;
        }

        public string Decrypt(string cipherText, int key)
        {
            string text = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                int x = (cipherText[i] - 'A' - key + 26) % 26;

                text += (char)(x + 'a');
            }
            return text;
        }


        public int Analyse(string plainText, string cipherText)
        {
            int k = 0;
            k = (((cipherText[0] + 32) - plainText[0]) + 26) % 26;
            return k;
        }
    }
}
