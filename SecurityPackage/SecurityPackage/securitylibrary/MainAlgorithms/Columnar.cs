using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int columns = key.Count;
            plainText = plainText.Replace(" ", "");
            int rows = (int)Math.Ceiling((double)plainText.Length / columns);
            char[,] arr = new char[rows, columns];
            int index = 0;
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    if (index < plainText.Length)
                    {
                        arr[i, j] = plainText[index++];
                    }
                    else
                        arr[i, j] = 'X';
                }
            }
            List<KeyValuePair<int, int>> keyWthIndex = new List<KeyValuePair<int, int>>();
            int idx = 0;
            foreach (int k in key)
            {
                keyWthIndex.Add(new KeyValuePair<int, int>(k, idx++));
            }
            keyWthIndex = keyWthIndex.OrderBy(pair => pair.Key).ToList();
            string cipherText = "";
            foreach (var pair in keyWthIndex)
            {
                int colIndex = pair.Value;
                for (int i = 0; i < rows; i++)
                {
                    cipherText += arr[i, colIndex];
                }
            }
            return cipherText.ToUpper();
        }
    }
}
