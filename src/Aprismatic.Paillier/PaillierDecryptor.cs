using System;
using System.Numerics;

namespace Aprismatic.Paillier
{
    public class PaillierDecryptor
    {
        private readonly PaillierKeyStruct _keyStruct;

        public PaillierDecryptor(PaillierKeyStruct keyStruct)
        {
            _keyStruct = keyStruct;
        }

        public BigInteger ProcessByteBlock(byte[] block)
        {
            var bBlock = new BigInteger(block.AsSpan(0, block.Length >> 1)); // div 2

            // calculate M
            // m = (c^lambda(mod nsquare) - 1) / n * mu (mod n)
            var L = (BigInteger.ModPow(bBlock, _keyStruct.Lambda, _keyStruct.NSquare) - BigInteger.One) / _keyStruct.N;
            var m = L * _keyStruct.Mu % _keyStruct.N;

            return m;
        }
    }
}
