using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
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
