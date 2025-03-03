using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int n = (int)Math.Sqrt(key.Count());
            List<int> keyInverse = new List<int>(new int[key.Count()]);
            int det = 0;
            //Negative Modulus
            int Mod(int x, int m)
            {
                int r = x % m;
                return r < 0 ? r + m : r;
            }
            //2*2 Matrix Inverse
            if (n == 2)
            {
                det = (key[0] * key[3] - key[1] * key[2]);
                det = Mod(det, 26);
                int modInverseCnt = 1;
                if (BigInteger.GreatestCommonDivisor(det, 26) == 1)
                    while (true)
                    {
                        int a = modInverseCnt * det;
                        Console.WriteLine(a + " " + modInverseCnt);
                        if (a % 26 == 1) break;
                        modInverseCnt++;
                    }
                else throw new SystemException();
                det = modInverseCnt;
                keyInverse[3] = key[0];
                keyInverse[0] = key[3];
                keyInverse[1] = -1 * key[1];
                keyInverse[2] = -1 * key[2];
                for (int i = 0; i < key.Count(); i++)
                {
                    keyInverse[i] = Mod(keyInverse[i], 26);
                    keyInverse[i] *= det;
                    keyInverse[i] = Mod(keyInverse[i], 26);
                }
            }
            //3*3 Matrix Inverse
            else if (n == 3)
            {
                int[,] matrix = new int[3, 3];
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        matrix[i, j] = key[i * n + j];
                    }
                }
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        keyInverse[i * n + j] = matrix[(i + 1) % n, (j + 1) % n] * matrix[(i + 2) % n, (j + 2) % n] -
                                                matrix[(i + 1) % n, (j + 2) % n] * matrix[(i + 2) % n, (j + 1) % n];
                    }
                }
                for (int i = 0; i < n; i++)
                {
                    det += matrix[0, i] * keyInverse[i];
                }
                List<int> temp = new List<int>(new int[key.Count()]);
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        temp[j * n + i] = keyInverse[i * n + j];
                    }
                }
                keyInverse = temp;
                det = Mod(det, 26);
                int modInverseCnt = 1;
                while (true)
                {
                    int a = modInverseCnt * det;
                    if (a % 26 == 1 || a == 100) break;
                    modInverseCnt++;
                }
                det = modInverseCnt;
                for (int i = 0; i < n * n; i++)
                {
                    keyInverse[i] = Mod(keyInverse[i], 26);
                    keyInverse[i] *= det;
                    keyInverse[i] %= 26;
                }
            }
            //Decryption
            List<int> plainText = new List<int>(new int[cipherText.Count()]);
            for (int i = 0; i < plainText.Count(); i = i + n)
            {
                for (int j = i; j < i + n; j++)
                {
                    for (int k = i; k < i + n; k++)
                    {
                        plainText[j] += cipherText[k] * keyInverse[(j % n) * n + k % n];
                    }
                }
            }
            for (int i = 0; i < plainText.Count(); i++)
            {
                plainText[i] %= 26;
            }
            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>(new int[plainText.Count()]);
            int n = (int)Math.Sqrt(key.Count());
            for (int i = 0; i < plainText.Count(); i = i + n)
            {
                for (int j = i; j < i + n; j++)
                {
                    for (int k = i; k < i + n; k++)
                    {
                        cipherText[j] += plainText[k] * key[(j % n) * n + k % n];
                    }
                }
            }
            for (int i = 0; i < cipherText.Count(); i++)
            {
                cipherText[i] %= 26;
            }
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

    }
}
