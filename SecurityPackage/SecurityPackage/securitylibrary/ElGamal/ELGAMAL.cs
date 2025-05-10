using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            // throw new NotImplementedException();
            long c1 = ModExp(alpha, k, q);
            long c2 = (ModExp(y, k, q) * m) % q;
            return new List<long> { c1, c2 };

        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            //throw new NotImplementedException();
            long temp = ModExp(c1, x, q);
            long inverse = ModExp(temp, q - 2, q);
            long m = (c2 * inverse) % q;
            return (int)m;

        }
        private long ModExp(long a, long b, long p)
        {
            long result = 1;
            a = a % p;
            while (b > 0)
            {
                if (b % 2 == 1)
                    result = (result * a) % p;
                a = (a * a) % p;
                b = b / 2;
            }
            return result;
        }
    }
}
