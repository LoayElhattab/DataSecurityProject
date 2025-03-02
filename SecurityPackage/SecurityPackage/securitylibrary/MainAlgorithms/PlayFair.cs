

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        private char[,] keyMatrix = new char[5, 5];

        public string Decrypt(string cipherText, string key)
        {
            String plainText = "a";
            return plainText.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            //convert string key to a matrix
            generateKeyMatrix(key);
            //convert plaintext to list of pairs
            List<string> pairs = convertPlainTextToListOfPairs(plainText);
            //encrypting the pairs
            string cipherText = "";
            foreach (String pair in pairs)
                cipherText += EncryptPair(pair[0], pair[1]);
            return cipherText;
        }

        private void generateKeyMatrix(string key)
        {
            key = key.ToUpper().Replace("J", "I");
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";//doesn't include j
            List<char> used = new List<char>();
            int row = 0;
            int column = 0;

            String appendedText = key + alphabet;
            foreach (char c in appendedText)
            {
                if (!used.Contains(c))
                {
                    keyMatrix[row,column] = c;
                    used.Add(c);
                    column++;
                    if(column==5)
                    {
                        column = 0;
                        row++;
                    }
                }
            }
          
        }

        private List<string> convertPlainTextToListOfPairs(string text)
        {
            text = text.ToUpper().Replace("J", "I");
            List<string> pairs = new List<string>();
            int i = 0;
            while (i < text.Length)
            {
                char first = text[i];
                char second = (i + 1 < text.Length) ? text[i + 1] : 'X';
                if (first == second)
                {
                    second = 'X';
                    i++;
                }
                else
                {
                    i += 2;
                }
                pairs.Add($"{first}{second}");
            }
          
            if (pairs[pairs.Count - 1].Length == 1)
                pairs[pairs.Count - 1] += 'X';
            return pairs;
        }

        private string EncryptPair(char a, char b)
        {
            int row1 = 0;
            int col1=0;
            int row2 = 0;
            int col2=0;

            FindPosition(a, ref row1,ref col1);
            FindPosition(b, ref row2,ref col2);
            
            //first case
            if (row1 == row2)
            {
                return keyMatrix[row1, (col1 + 1) % 5].ToString() + keyMatrix[row2, (col2 + 1) % 5].ToString();
            }
            //second case
            else if (col1 == col2)
            {
                return keyMatrix[(row1 + 1) % 5, col1].ToString() + keyMatrix[(row2 + 1) % 5, col2].ToString();
            }
            //third case
            else
            {
                return keyMatrix[row1, col2].ToString() + keyMatrix[row2, col1].ToString();
            }
        }

        private void  FindPosition(char c, ref int a,ref int b)
        {
            for (int row = 0; row < 5; row++)
                for (int col = 0; col < 5; col++)
                    if (keyMatrix[row, col] == c)
                    {
                        a = row; b = col;
                    }
          
        }
    }
}