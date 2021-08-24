using System;
using System.Numerics;

namespace Aprismatic.PaillierExt
{
    public class PaillierDecryptor
    {
        private readonly PaillierKeyStruct _keyStruct;

        public PaillierDecryptor(PaillierKeyStruct keyStruct)
        {
            _keyStruct = keyStruct;
        }

        public BigFraction ProcessByteBlock(byte[] block)
        {
            var bBlock = new BigInteger(block.AsSpan(0, block.Length >> 1)); // div 2

            // calculate M
            // m = (c^lambda(mod nsquare) - 1) / n * mu (mod n)
            var L = (BigInteger.ModPow(bBlock, _keyStruct.Lambda, _keyStruct.NSquare) - BigInteger.One) / _keyStruct.N;
            var m = L * _keyStruct.Mu % _keyStruct.N;

            return Decode(m);
        }

        public BigFraction Decode(BigInteger n) // TODO: Add tests now that this method is public
        {
            var a = new BigFraction(n, _keyStruct.PlaintextExp);
            a %= _keyStruct.MaxRawPlaintext + BigInteger.One;
            if (a > _keyStruct.MaxEncryptableValue)
                a = a - _keyStruct.MaxRawPlaintext - BigFraction.One;
            return a;
        }
    }
}
