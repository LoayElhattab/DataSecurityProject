using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            // throw new NotImplementedException();
            int ya = ModExp(alpha, xa, q); // Party A's public key
            int yb = ModExp(alpha, xb, q); // Party B's public key

            int keyA = ModExp(yb, xa, q); // Party A's shared key
            int keyB = ModExp(ya, xb, q); // Party B's shared key

            return new List<int> { keyA, keyB };
        }
        private int ModExp(int a, int b, int p)
        {
            long result = 1;
            long baseValue = a % p;
            long exponent = b;

            while (exponent > 0)
            {
                if (exponent % 2 == 1)
                    result = (result * baseValue) % p;
                baseValue = (baseValue * baseValue) % p;
                exponent = exponent / 2;
            }
            return (int)result;
        }   
    }
}
