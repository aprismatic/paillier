using System.Numerics;

namespace PaillierExt.Homomorphism
{
    public static class PaillierHomomorphism
    {
        public static byte[] Addition(byte[] p_first, byte[] p_second, byte[] p_NSquare)
        {
            var A = new BigInteger(p_first);
            var B = new BigInteger(p_second);
            var NSquare = new BigInteger(p_NSquare);

            var bi_res = (A * B) % NSquare;
            var res = bi_res.ToByteArray();
            return res;
        }
    }
}
