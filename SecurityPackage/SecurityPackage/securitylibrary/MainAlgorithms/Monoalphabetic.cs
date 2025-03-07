using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {

            Dictionary<char, char> data = new Dictionary<char, char>();

            for (int i = 0; i < plainText.Length; i++)
            {

                if (!data.ContainsKey(plainText[i]))
                {

                    data[plainText[i]] = (char)(cipherText[i] + 32);
                }
            }


            HashSet<char> usedChar = new HashSet<char>(data.Values);


            for (char i = 'a'; i <= 'z'; i++)
            {
                if (!data.ContainsKey(i))
                {
                    for (char j = 'a'; j <= 'z'; j++)
                    {
                        if (!usedChar.Contains(j))
                        {
                            data[i] = j;
                            usedChar.Add(j);
                            break;
                        }
                    }
                }
            }


            string key = "";
            for (char c = 'a'; c <= 'z'; c++)
            {
                key += data[c];
            }

            return key;
        }




        public string Decrypt(string cipherText, string key)
        {
            string text = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (cipherText[i] + 32 == key[j])
                    {
                        text += (char)(j + 'a');
                        break;
                    }
                }

            }
            return text;

        }

        public string Encrypt(string plainText, string key)
        {
            string cipher = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                int currentchar = plainText[i] - 'a';
                cipher += key[currentchar];
            }
            return cipher;

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string key = "";
            char[] freq = { 'e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'l', 'd', 'c', 'u', 'm', 'f', 'p', 'g', 'w', 'y', 'b', 'v', 'k', 'x', 'j', 'q', 'z' };

            Dictionary<char, int> data = new Dictionary<char, int>();

            for (int i = 0; i < cipher.Length; i++)
            {

                if (data.ContainsKey(cipher[i]))
                {

                    data[cipher[i]]++;
                }
                else
                {
                    data[cipher[i]] = 0;
                }

            }
            var sortedData = data.OrderByDescending(pair => pair.Value).ToList();

            Dictionary<char, char> newData = new Dictionary<char, char>();

            for (int i = 0; i < sortedData.Count; i++)
            {
                newData[sortedData[i].Key] = freq[i];
            }




            for (int i = 0; i < cipher.Length; i++)
            {

                key += newData[cipher[i]];

            }


            return key;
        }
    }
}