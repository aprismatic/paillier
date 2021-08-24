using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Aprismatic.PaillierExt
{
    public class PaillierEncryptor : IDisposable
    {
        private readonly RandomNumberGenerator rng;
        private readonly PaillierKeyStruct _keyStruct;

        public PaillierEncryptor(PaillierKeyStruct keyStruct)
        {
            rng = RandomNumberGenerator.Create();
            _keyStruct = keyStruct;
        }

        public void ProcessBigFraction(BigFraction message, Span<byte> res)
        {
            if (message.Denominator > _keyStruct.PlaintextExp)
            {
                var denominator = _keyStruct.PlaintextExp;
                var numerator = message.Numerator * denominator / message.Denominator;
                message = new BigFraction(numerator, denominator);
            }

            if (BigInteger.Abs(message.Numerator) > _keyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Numerator to encrypt is too large. Message should be |m| < 2^{_keyStruct.MaxPlaintextBits - 1}");

            // generate random R
            var R = BigInteger.Zero.GenRandomBits(_keyStruct.NBitCount - 1, rng); // R's bitlength is n-1 so that r is within Zn

            // ciphertext c = g^m * r^n mod n^2
            var RN = BigInteger.ModPow(R, _keyStruct.N, _keyStruct.NSquare);

            // if we use simple key generation (g = n + 1), we can use
            // (n+1)^m = n*m + 1  mod n^2
            var Gm = (_keyStruct.N * Encode(message) + BigInteger.One) % _keyStruct.NSquare;
            var Gm_Neg = (_keyStruct.N * Encode(-message) + BigInteger.One) % _keyStruct.NSquare;

            var C = (Gm * RN) % _keyStruct.NSquare;
            var C_Neg = (Gm_Neg * RN) % _keyStruct.NSquare;

            var lgth = res.Length >> 1;
            C.TryWriteBytes(res.Slice(0, lgth), out _);
            C_Neg.TryWriteBytes(res.Slice(lgth, lgth), out _);
        }

        public BigInteger Encode(BigFraction a) // TODO: Add tests now that this method is public
        {
            if (a < BigFraction.Zero)
                a = a + _keyStruct.MaxRawPlaintext + BigFraction.One;
            a *= _keyStruct.PlaintextExp;
            return a.ToBigInteger();
        }

        public void Dispose() => rng.Dispose();
    }
}
