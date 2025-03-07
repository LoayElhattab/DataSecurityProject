using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Runtime.Remoting.Messaging;
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
            List<int> plainTextInverse = new List<int>(new int[4]);
            List<int> cipherTextEquiv = new List<int>(new int[4]);
            int det = 0;
            //Negative Modulus
            int Mod(int x, int m)
            {
                int r = x % m;
                return r < 0 ? r + m : r;
            }
            //2*2 Matrix Inverse
            int i = 0, j = 0;
            bool flag = false;
            for (i = 0; i < plainText.Count - 3; i += 2)
            {
                for (j = i + 2; j < plainText.Count - 1; j += 2)
                {
                    det = (plainText[i] * plainText[j + 1] - plainText[i + 1] * plainText[j]);
                    det = Mod(det, 26);
                    int modInverseCnt = 1;
                    if (BigInteger.GreatestCommonDivisor(det, 26) == 1)
                    {
                        while (true)
                        {
                            int a = modInverseCnt * det;
                            if (a % 26 == 1) break;
                            modInverseCnt++;
                        }
                        det = modInverseCnt;
                        flag = true;
                        break;
                    }
                }
                if (flag) break;
            }
            if (!flag) throw new InvalidAnlysisException();
            plainTextInverse[3] = plainText[i];
            plainTextInverse[0] = plainText[j + 1];
            plainTextInverse[1] = -1 * plainText[i + 1];
            plainTextInverse[2] = -1 * plainText[j];
            cipherTextEquiv[0] = cipherText[i];
            cipherTextEquiv[3] = cipherText[j + 1];
            cipherTextEquiv[1] = cipherText[i + 1];
            cipherTextEquiv[2] = cipherText[j];
            for (i = 0; i < plainTextInverse.Count(); i++)
            {
                plainTextInverse[i] = Mod(plainTextInverse[i], 26);
                plainTextInverse[i] *= det;
                plainTextInverse[i] = Mod(plainTextInverse[i], 26);
            }
            //Key Calculation
            List<int> key = new List<int>(new int[4]);
            key[0] = cipherTextEquiv[0] * plainTextInverse[0] + cipherTextEquiv[2] * plainTextInverse[1];
            key[1] = cipherTextEquiv[0] * plainTextInverse[2] + cipherTextEquiv[2] * plainTextInverse[3];
            key[2] = cipherTextEquiv[1] * plainTextInverse[0] + cipherTextEquiv[3] * plainTextInverse[1];
            key[3] = cipherTextEquiv[1] * plainTextInverse[2] + cipherTextEquiv[3] * plainTextInverse[3];
            for (i = 0; i < key.Count(); i++)
            {
                key[i] = Mod(key[i], 26);
            }
            return key;
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
            List<int> plainTextInverse = new List<int>(new int[9]);
            int det = 0;
            //Negative Modulus
            int Mod(int x, int m)
            {
                int r = x % m;
                return r < 0 ? r + m : r;
            }
            //Vertical to Horizontal
            List<int> plainText2 = new List<int>() { plainText[0], plainText[3], plainText[6], plainText[1], plainText[4], plainText[7], plainText[2], plainText[5], plainText[8] };
            List<int> cipherText2 = new List<int>() { cipherText[0], cipherText[3], cipherText[6], cipherText[1], cipherText[4], cipherText[7], cipherText[2], cipherText[5], cipherText[8] };
            //3*3 Matrix Inverse
            int[,] matrix = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    matrix[i, j] = plainText2[i * 3 + j];
                }
            }
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    plainTextInverse[i * 3 + j] = matrix[(i + 1) % 3, (j + 1) % 3] * matrix[(i + 2) % 3, (j + 2) % 3] -
                                            matrix[(i + 1) % 3, (j + 2) % 3] * matrix[(i + 2) % 3, (j + 1) % 3];
                }
            }
            for (int i = 0; i < 3; i++)
            {
                det += matrix[0, i] * plainTextInverse[i];
            }
            List<int> temp = new List<int>(new int[plainText2.Count()]);
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    temp[j * 3 + i] = plainTextInverse[i * 3 + j];
                }
            }
            plainTextInverse = temp;
            det = Mod(det, 26);
            int modInverseCnt = 1;
            while (true)
            {
                int a = modInverseCnt * det;
                if (a % 26 == 1 || a == 100) break;
                modInverseCnt++;
            }
            det = modInverseCnt;
            for (int i = 0; i < 3 * 3; i++)
            {
                plainTextInverse[i] = Mod(plainTextInverse[i], 26);
                plainTextInverse[i] *= det;
                plainTextInverse[i] %= 26;
            }
            //Key Calculation
            List<int> key = new List<int>(new int[9]);
            key[0] = cipherText2[0] * plainTextInverse[0] + cipherText2[1] * plainTextInverse[3] + cipherText2[2] * plainTextInverse[6];
            key[1] = cipherText2[0] * plainTextInverse[1] + cipherText2[1] * plainTextInverse[4] + cipherText2[2] * plainTextInverse[7];
            key[2] = cipherText2[0] * plainTextInverse[2] + cipherText2[1] * plainTextInverse[5] + cipherText2[2] * plainTextInverse[8];
            key[3] = cipherText2[3] * plainTextInverse[0] + cipherText2[4] * plainTextInverse[3] + cipherText2[5] * plainTextInverse[6];
            key[4] = cipherText2[3] * plainTextInverse[1] + cipherText2[4] * plainTextInverse[4] + cipherText2[5] * plainTextInverse[7];
            key[5] = cipherText2[3] * plainTextInverse[2] + cipherText2[4] * plainTextInverse[5] + cipherText2[5] * plainTextInverse[8];
            key[6] = cipherText2[6] * plainTextInverse[0] + cipherText2[7] * plainTextInverse[3] + cipherText2[8] * plainTextInverse[6];
            key[7] = cipherText2[6] * plainTextInverse[1] + cipherText2[7] * plainTextInverse[4] + cipherText2[8] * plainTextInverse[7];
            key[8] = cipherText2[6] * plainTextInverse[2] + cipherText2[7] * plainTextInverse[5] + cipherText2[8] * plainTextInverse[8];
            for (int i = 0; i < key.Count(); i++)
            {
                key[i] = Mod(key[i], 26);
            }
            return key;
        }
    }
}
