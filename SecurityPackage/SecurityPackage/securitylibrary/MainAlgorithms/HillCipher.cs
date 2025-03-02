using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            int n = (int)Math.Sqrt(key.Count());
            for (int i = 0; i < plainText.Count(); i = i + n)
            {
                for (int j = i; j < i + n; j++)
                {
                    cipherText.Add(0);
                    for (int k = i; k < i + n; k++)
                    {
                        cipherText[j] += plainText[k] * key[(j % n) * n + k % n];
                    }
                }
            }
            for (int i = 0; i < cipherText.Count(); i++)
            {
                cipherText[i] = cipherText[i] % 26;
            }
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

    }
}
