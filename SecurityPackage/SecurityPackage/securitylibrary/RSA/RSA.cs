using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            return ModPow(M, e, n);
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi = (p - 1) * (q - 1);
            int d = GetMultiplicativeInverse(e, phi);
            return ModPow(C, d, n);
        }

        private int ModPow(int baseValue, int exponent, int modulus)
        {
            long result = 1;
            long baseNum = baseValue % modulus;

            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                {
                    result = (result * baseNum) % modulus;
                }
                baseNum = (baseNum * baseNum) % modulus;
                exponent = exponent / 2;
            }

            return (int)result;
        }


        public int GetMultiplicativeInverse(int number, int baseN)
        {
            if (GCD(number, baseN) != 1)
                return -1;

            int inverse = 0, newInverse = 1;
            int remainder = baseN, newRemainder = number;

            while (newRemainder != 0)
            {
                int quotient = remainder / newRemainder;

                int tempInverse = inverse;
                inverse = newInverse;
                newInverse = tempInverse - quotient * newInverse;

                int tempRemainder = remainder;
                remainder = newRemainder;
                newRemainder = tempRemainder - quotient * newRemainder;
            }

            if (inverse < 0)
                inverse += baseN;

            return inverse;
        }

        public int GCD(int a, int b)
        {
            while (b != 0)
            {
                int temp = b;
                b = a % b;
                a = temp;
            }
            return a;
        }
    }
}
