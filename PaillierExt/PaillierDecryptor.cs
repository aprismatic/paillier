using System.Numerics;
using Aprismatic.BigFraction;

namespace PaillierExt
{
    public class PaillierDecryptor : PaillierAbstractCipher
    {
        public PaillierDecryptor(PaillierKeyStruct keyStruct)
            : base(keyStruct)
        {
        }

        //TODO: check again for decryption
        public BigFraction ProcessByteBlock(byte[] block)
        {
            var bBlock = new BigInteger(block);

            // calculate M
            // m = (c^lambda(mod nsquare) - 1) / n * miu (mod n)
            var m = (BigInteger.ModPow(bBlock, KeyStruct.Lambda, KeyStruct.NSquare) - 1) / KeyStruct.N * KeyStruct.Miu % KeyStruct.N;

            return Decode(m);
        }

        private BigFraction Decode(BigInteger n)
        {
            var a = new BigFraction(n, KeyStruct.PlaintextExp);
            a = a % (KeyStruct.MaxRawPlaintext + 1);
            if ( a > KeyStruct.MaxRawPlaintext / 2)
                a = a - KeyStruct.MaxRawPlaintext - 1;
            return a;
        }
    }
}
