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

        public BigFraction ProcessByteBlockOld(byte[] block)
        {
            var block_half = new byte[block.Length / 2];
            Array.Copy(block, block_half, block.Length / 2);
            var bBlock = new BigInteger(block_half);

            // calculate M
            // m = (c^lambda(mod nsquare) - 1) / n * miu (mod n)
            var m = (BigInteger.ModPow(bBlock, _keyStruct.Lambda, _keyStruct.NSquare) - 1) / _keyStruct.N * _keyStruct.Miu % _keyStruct.N;

            return Decode(m);
        }

        public BigFraction ProcessByteBlock(byte[] block)
        {
            var bBlock = new BigInteger(block.AsSpan(0, block.Length >> 1)); // div 2

            // calculate M
            // m = (c^lambda(mod nsquare) - 1) / n * miu (mod n)
            var L = (BigInteger.ModPow(bBlock, _keyStruct.Lambda, _keyStruct.NSquare) - BigInteger.One) / _keyStruct.N;
            var m = L * _keyStruct.Miu % _keyStruct.N;

            return Decode(m);
        }

        private BigFraction Decode(BigInteger n)
        {
            var a = new BigFraction(n, PaillierKeyStruct.PlaintextExp);
            a %= (PaillierKeyStruct.MaxRawPlaintext + 1);
            if (a > PaillierKeyStruct.MaxEncryptableValue)
                a = a - PaillierKeyStruct.MaxRawPlaintext - BigInteger.One;
            return a;
        }
    }
}
