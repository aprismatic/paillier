using System.Collections.Generic;

namespace PaillierExt.Homomorphism
{
    public static class PaillierHomomorphism
    {
        public static byte[] Addition(byte[] p_first, byte[] p_second, byte[] p_N)
        {
            var A = new BigInteger(p_first);
            var B = new BigInteger(p_second);
            var N = new BigInteger(p_N);

            var bi_res = A * B % (N * N);
            var res = bi_res.getBytes();
            return res;
        }
    }
}
