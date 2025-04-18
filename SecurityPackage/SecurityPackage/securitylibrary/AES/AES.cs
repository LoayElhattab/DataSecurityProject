using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            byte[,] statePlainText = BlockToState(plainText);
            byte[,] stateKey = BlockToState(key);
            List<byte[,]> keys = new List<byte[,]>();
            keys.Add(GenerateKey(stateKey, 0));
            for(int i = 1; i < 10; i++)
            {
                keys.Add(GenerateKey(keys.Last(), i));
            }
            statePlainText = AddRoundKey(statePlainText, stateKey);
            for(int i = 0; i < 9; i++)
            {
                statePlainText = AddRoundKey(MixColumns(ShiftRows(SubBytes(statePlainText))), keys[i]); 
            }
            statePlainText = AddRoundKey(ShiftRows(SubBytes(statePlainText)), keys[9]);
            string cipherText = StateToBlock(statePlainText);
            return cipherText;
        }

        public byte[,] BlockToState(string plainText)
        {
            string plainTextCleaned = plainText.Remove(0, 2);
            byte[] plainTextBytes = Enumerable.Range(0, plainTextCleaned.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(plainTextCleaned.Substring(x, 2), 16))
                         .ToArray();
            byte[,] state = new byte[4, 4];
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    state[j, i] = plainTextBytes[i * 4 + j];
                }
            }
            return state;
        }

        readonly byte[,] sBox = new byte[16, 16] {
                //   0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
                { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 }, // 0
                { 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 }, // 1
                { 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 }, // 2
                { 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 }, // 3
                { 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 }, // 4
                { 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF }, // 5
                { 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 }, // 6
                { 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 }, // 7
                { 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 }, // 8
                { 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB }, // 9
                { 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 }, // A
                { 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 }, // B
                { 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A }, // C
                { 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E }, // D
                { 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF }, // E
                { 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 }  // F
            };

        public byte[,] SubBytes(byte[,] state)
        {
            for (int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    state[i, j] = sBox[state[i, j] >> 4, state[i, j] & 0x0f];
                }
            }
            return state;
        }
        
        public byte[,] ShiftRows(byte[,] state)
        {
            byte temp1 = state[1, 0];
            state[1, 0] = state[1, 1];
            state[1, 1] = state[1, 2];
            state[1, 2] = state[1, 3];
            state[1, 3] = temp1;
            byte temp21 = state[2, 0];
            byte temp22 = state[2, 1];
            state[2, 0] = state[2, 2];
            state[2, 1] = state[2, 3];
            state[2, 2] = temp21;
            state[2, 3] = temp22;
            byte temp3 = state[3, 3];
            state[3, 3] = state[3, 2];
            state[3, 2] = state[3, 1];
            state[3, 1] = state[3, 0];
            state[3, 0] = temp3;
            return state;
        }

        public byte[,] MixColumns(byte[,] state)
        {
            byte[,] newState = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                newState[0, i] = (byte)(GFMultiply(state[0, i], 0x02) ^ GFMultiply(state[1, i], 0x03) ^ state[2, i] ^ state[3, i]);
                newState[1, i] = (byte)(state[0, i] ^ GFMultiply(state[1, i], 0x02) ^ GFMultiply(state[2, i], 0x03) ^ state[3, i]);
                newState[2, i] = (byte)(state[0, i] ^ state[1, i] ^ GFMultiply(state[2, i], 0x02) ^ GFMultiply(state[3, i], 0x03));
                newState[3, i] = (byte)(GFMultiply(state[0, i], 0x03) ^ state[1, i] ^ state[2, i] ^ GFMultiply(state[3, i], 0x02));
            }
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    state[i, j] = newState[i, j];
            return state;
        }

        public byte GFMultiply(byte a, byte b)
        {
            if (b == 0x02) return (byte)((a << 1) ^ (a >= 0x80 ? 0x1B : 0x00));
            else return (byte)((a << 1) ^ (a >= 0x80 ? 0x1B : 0x00) ^ a);
        } 

        public byte[,] AddRoundKey(byte[,] state, byte[,] key)
        {
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    state[i, j] ^= key[i, j];
                }
            }
            return state;
        }

        public byte[,] GenerateKey(byte[,] oldKey, int round)
        {
            byte[] Rcon = new byte[] {
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
            };
            byte[,] newKey = new byte[4, 4];
            for(int i = 0; i < 3; i++)
            {
                newKey[i, 0] = oldKey[i + 1, 3];
            }
            newKey[3, 0] = oldKey[0, 3];
            for (int i = 0; i < 4; i++)
            {
                newKey[i, 0] = sBox[newKey[i, 0] >> 4, newKey[i, 0] & 0x0f];
                newKey[i, 0] = (byte)(newKey[i, 0] ^ oldKey[i, 0] ^ (i == 0 ? Rcon[round] : 0));
            }
            for(int i = 1; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    newKey[j, i] = (byte)(newKey[j, i - 1] ^ oldKey[j, i]);
                }
            }
            return newKey;
        }

        public string StateToBlock(byte[,] state)
        {
            byte[] blockBytes = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    blockBytes[i * 4 + j] = state[j, i];
                }
            }
            string hexString = "0x" + BitConverter.ToString(blockBytes).Replace("-", "");
            return hexString;
        }
    }
}
