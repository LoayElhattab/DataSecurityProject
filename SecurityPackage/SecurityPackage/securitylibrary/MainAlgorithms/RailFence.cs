using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            for (int key = 1; key <= plainText.Length; key++)
            {
                string s = Encrypt(plainText, key);
                if (s.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                    return key;
            }
            return -1;
        }

        public string Decrypt(string cipherText, int key)
        {
            int n = cipherText.Length, c, idx = 0;
            string[] newText = new string[key];

            int remain = n % key;

            for (int i = 0; i < key; i++)
            {
                c = n / key;
                if (remain != 0)
                {
                    c += 1;
                    remain--;
                }
                newText[i] = cipherText.Substring(idx, c);
                idx += c;
            }

            string plainText = "", firstString = newText[0];

            for (int i = 0; i < firstString.Length; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    string s = newText[j];
                    if (newText[j] != null && i < s.Length)
                    {
                        plainText += newText[j][i];
                    }
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            int n = plainText.Length;

            if (key <= 1)
                return plainText;

            plainText = plainText.Replace(" ", "");
            plainText = plainText.ToUpper();

            string[] newText = new string[key];

            int pos = 0, end = key;

            foreach (char c in plainText)
            {
                newText[pos++] += c;
                if (pos == end)
                    pos = 0;
            }

            string cipher = "";

            for (int i = 0; i < key; i++)
            {
                cipher += newText[i];
            }

            return cipher;

        }
    }
}

