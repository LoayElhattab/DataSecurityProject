using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            string binaryCipherText = HexToBin(cipherText);
            string binaryKey = HexToBin(key);
            string binaryCipherTextPermuted = InitialPermutation(binaryCipherText);
            List<string> subKeys = SubKeysGeneration(binaryKey);
            string leftCipherText = binaryCipherTextPermuted.Substring(0, 32);
            string rightCipherText = binaryCipherTextPermuted.Substring(32, 32);
            for (int i = 15; i >= 0; i--)
            {
                List<string> decryptedText = EncryptionRound(leftCipherText, rightCipherText, subKeys[i]);
                leftCipherText = decryptedText[0];
                rightCipherText = decryptedText[1];
            }
            string binaryPlainText = FinalPermutation(rightCipherText + leftCipherText);
            return BinToHex(binaryPlainText);
        }

        public override string Encrypt(string plainText, string key)
        {
            string binaryPlainText = HexToBin(plainText);
            string binaryKey = HexToBin(key);
            string binaryPlainTextPermuted = InitialPermutation(binaryPlainText);
            List<string> subKeys = SubKeysGeneration(binaryKey);
            string leftPlainText = binaryPlainTextPermuted.Substring(0, 32);
            string rightPlainText = binaryPlainTextPermuted.Substring(32, 32);
            for (int i = 0; i < 16; i++)
            {
                List<string> encryptedText = EncryptionRound(leftPlainText, rightPlainText, subKeys[i]);
                leftPlainText = encryptedText[0];
                rightPlainText = encryptedText[1];
            }
            string cipherText = FinalPermutation(rightPlainText + leftPlainText);
            cipherText = BinToHex(cipherText);
            return cipherText;
        }

        public string InitialPermutation(string plainText)
        {
            char[] initialPermutation = new char[64];
            int[] initialPermutationTable = {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9,  1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            };
            for (int i = 0; i < 64; i++)
            {
                initialPermutation[i] = plainText[initialPermutationTable[i] - 1];
            }
            string plainTextPermuted = new string(initialPermutation);
            return plainTextPermuted;
        }

        public List<string> EncryptionRound(string left, string right, string key)
        {
            string nextLeft = right;
            string nextRight = Xor(left, ManglerFunction(right, key), 32);
            List<string> leftAndRightKeys = new List<string>
            {
                nextLeft,
                nextRight
            };
            return leftAndRightKeys;
        }

        public string ManglerFunction(string right, string key)
        {
            string expandedRight = Expansion(right);
            string xoredRight = Xor(expandedRight, key, 48);
            string sboxedRight = Substitution(xoredRight);
            string permutedRight = Permutation(sboxedRight);
            return permutedRight;
        }
        public string Expansion(string permutedPlainText)
        {
            char[] expandedRight = new char[48];
            int[] expansionTable = {
                32,  1,  2,  3,  4,  5,
                4,  5,  6,  7,  8,  9,
                8,  9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32,  1
            };
            for (int i = 0; i < 48; i++)
            {
                expandedRight[i] = permutedPlainText[expansionTable[i] - 1]; // E-table is 1-based
            }
            string expandedPlainText = new string(expandedRight);
            return expandedPlainText;
        }

        public string Substitution(string right)
        {
            int[,,] sBoxes = new int[,,]
            {
                {
                    { 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                    { 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                    { 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                    { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
                },
                {
                    { 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                    { 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                    { 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                    { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
                },
                {
                    { 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                    { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                    { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                    { 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
                },
                {
                    { 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                    { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                    { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                    { 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
                },
                {
                    { 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                    { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                    { 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                    { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
                },
                {
                    { 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                    { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                    { 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                    { 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
                },
                {
                    { 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                    { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                    { 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                    { 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
                },
                {
                    { 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                    { 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                    { 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                    { 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
                }
            };
            StringBuilder sBoxOutput = new StringBuilder();
            for (int i = 0; i < 8; i++)
            {
                int startIdx = i * 6;
                string chunk = right.Substring(startIdx, 6);
                int row = Convert.ToInt32($"{chunk[0]}{chunk[5]}", 2);
                int col = Convert.ToInt32(chunk.Substring(1, 4), 2);
                int sBoxValue = sBoxes[i, row, col];
                sBoxOutput.Append(Convert.ToString(sBoxValue, 2).PadLeft(4, '0'));
            }
            return sBoxOutput.ToString();
        }

        public string Permutation(string sBoxOutput)
        {
            char[] permutedSBox = new char[32];
            int[] permutationTable = {
                16,  7,   20,  21,  29,  12,  28,  17,
                1,   15,  23,  26,  5,   18,  31,  10,
                2,   8,   24,  14,  32,  27,  3,   9,
                19,  13,  30,  6,   22,  11,  4,   25
            };
            for (int i = 0; i < 32; i++)
            {
                permutedSBox[i] = sBoxOutput[permutationTable[i] - 1];
            }
            return new string(permutedSBox);
        }
        public string FinalPermutation(string encryptedText)
        {
            char[] finalPermutation = new char[64];
            int[] finalPermutationTable = {
                40,  8,   48,  16,  56,  24,  64,  32,
                39,  7,   47,  15,  55,  23,  63,  31,
                38,  6,   46,  14,  54,  22,  62,  30,
                37,  5,   45,  13,  53,  21,  61,  29,
                36,  4,   44,  12,  52,  20,  60,  28,
                35,  3,   43,  11,  51,  19,  59,  27,
                34,  2,   42,  10,  50,  18,  58,  26,
                33,  1,   41,  9,   49,  17,  57,  25
            };
            for (int i = 0; i < 64; i++)
            {
                finalPermutation[i] = encryptedText[finalPermutationTable[i] - 1];
            }
            string cipherText = new string(finalPermutation);
            return cipherText;
        }
        public List<string> SubKeysGeneration(string key)
        {
            List<List<string>> keyTo56BitKeys = new List<List<string>>();
            List<string> C0D0 = PermutedChoice1(key);
            string C = circularLeftShift(C0D0[0], 1);
            string D = circularLeftShift(C0D0[1], 1);
            keyTo56BitKeys.Add(new List<string> { C, D });
            int[] shiftAmounts = { 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            for (int i = 0; i < 15; i++)
            {
                int amount = shiftAmounts[i];
                string prevC = keyTo56BitKeys[i][0];
                string prevD = keyTo56BitKeys[i][1];
                string newC = circularLeftShift(prevC, amount);
                string newD = circularLeftShift(prevD, amount);
                keyTo56BitKeys.Add(new List<string> { newC, newD });
            }
            List<string> subKeys = new List<string>();
            for (int i = 0; i < 16; i++)
            {
                subKeys.Add(PermutedChoice2(keyTo56BitKeys[i]));
            }
            return subKeys;
        }

        public List<string> PermutedChoice1(string key)
        {
            char[] left = new char[28];
            char[] right = new char[28];
            int[] permutedChoice1Table = {
                57,  49,  41,  33,  25,  17,  9,
                1,   58,  50,  42,  34,  26,  18,
                10,  2,   59,  51,  43,  35,  27,
                19,  11,  3,   60,  52,  44,  36,
                63,  55,  47,  39,  31,  23,  15,
                7,   62,  54,  46,  38,  30,  22,
                14,  6,   61,  53,  45,  37,  29,
                21,  13,  5,   28,  20,  12,  4

            };
            for (int i = 0; i < 56; i++)
            {
                if (i < 28) left[i] = key[permutedChoice1Table[i] - 1];
                else right[i - 28] = key[permutedChoice1Table[i] - 1];
            }
            string leftKey = new string(left);
            string rightKey = new string(right);
            List<string> keyPermutedChoice1 = new List<string> { leftKey, rightKey };
            return keyPermutedChoice1;
        }


        public string PermutedChoice2(List<string> leftAndRightKeys)
        {
            string permutedChoice1Key = leftAndRightKeys[0] + leftAndRightKeys[1];
            char[] subKey = new char[48];
            int[] permutedChoice2Table = {
                14,  17,  11,  24,  1,   5,
                3,   28,  15,  6,   21,  10,
                23,  19,  12,  4,   26,  8,
                16,  7,   27,  20,  13,  2,
                41,  52,  31,  37,  47,  55,
                30,  40,  51,  45,  33,  48,
                44,  49,  39,  56,  34,  53,
                46,  42,  50,  36,  29,  32
            };
            for (int i = 0; i < 48; i++)
            {
                subKey[i] = permutedChoice1Key[permutedChoice2Table[i] - 1];
            }
            string subKeyPermuted = new string(subKey);
            return subKeyPermuted;
        }

        public string circularLeftShift(string key, int amount)
        {
            string leftShiftedKey = key.Substring(amount, key.Length - amount) + key.Substring(0, amount);
            return leftShiftedKey;
        }
        public string HexToBin(string hex)
        {
            string hexCleaned = hex.Remove(0, 2);
            string binary = String.Join(String.Empty,
                hexCleaned.Select(
                    c => Convert.ToString(Convert.ToInt32(c.ToString(), 16), 2).PadLeft(4, '0')
                )
            );
            return binary;
        }
        public string BinToHex(string binary)
        {
            int pad = (4 - (binary.Length % 4)) % 4;
            binary = new string('0', pad) + binary;
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < binary.Length; i += 4)
            {
                string chunk = binary.Substring(i, 4);
                int num = Convert.ToInt32(chunk, 2);
                string hexDigit = num.ToString("X");
                hex.Append(hexDigit);
            }
            return "0x" + hex.ToString();
        }

        public string Xor(string a, string b, int n)
        {
            string ans = "";
            for (int i = 0; i < n; i++)
            {
                if (a[i] == b[i]) ans += "0";
                else ans += "1";
            }
            return ans;
        }
    }
}
