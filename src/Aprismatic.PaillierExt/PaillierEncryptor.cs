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

        public byte[] ProcessBigIntegerOld(BigFraction message)
        {
            if (message.Denominator > PaillierKeyStruct.PlaintextExp)
            {
                BigInteger denominator = PaillierKeyStruct.PlaintextExp;
                BigInteger numerator = message.Numerator * denominator / message.Denominator;
                message = new BigFraction(numerator, denominator);
            }

            if (BigInteger.Abs(message.Numerator) > PaillierKeyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Numerator to encrypt is too large. Message should be |m| < 2^{PaillierKeyStruct.MaxPlaintextBits - 1}");

            // generate random R
            var R = new BigInteger();
            R = R.GenRandomBits(_keyStruct.N.BitCount() - 1, rng); // R's bitlength is n-1 so that r is within Zn

            // ciphertext c = g^m * r^n mod n^2
            var RN = BigInteger.ModPow(R, _keyStruct.N, _keyStruct.NSquare);

            // if we use simple key generation (g = n + 1), we can use
            // (n+1)^m = n*m + 1  mod n^2
            var Gm = (_keyStruct.N * Encode(message) + 1) % _keyStruct.NSquare;
            var Gm_Neg = (_keyStruct.N * Encode(-message) + 1) % _keyStruct.NSquare;

            var C = (Gm * RN) % _keyStruct.NSquare;
            var C_Neg = (Gm_Neg * RN) % _keyStruct.NSquare;

            var res = new byte[_keyStruct.CiphertextBlocksize * 2];
            var c_bytes = C.ToByteArray();
            var c_Neg_bytes = C_Neg.ToByteArray();

            Array.Copy(c_bytes, 0, res, 0, c_bytes.Length);
            Array.Copy(c_Neg_bytes, 0, res, _keyStruct.CiphertextBlocksize, c_Neg_bytes.Length);

            return res;
        }

        public void ProcessBigInteger(BigFraction message, Span<byte> res)
        {
            if (message.Denominator > PaillierKeyStruct.PlaintextExp)
            {
                var denominator = PaillierKeyStruct.PlaintextExp;
                var numerator = message.Numerator * denominator / message.Denominator;
                message = new BigFraction(numerator, denominator);
            }

            if (BigInteger.Abs(message.Numerator) > PaillierKeyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Numerator to encrypt is too large. Message should be |m| < 2^{PaillierKeyStruct.MaxPlaintextBits - 1}");

            // generate random R
            var R = BigInteger.Zero.GenRandomBits(_keyStruct.NBitCount - 1, rng); // R's bitlength is n-1 so that r is within Zn

            // ciphertext c = g^m * r^n mod n^2
            var RN = BigInteger.ModPow(R, _keyStruct.N, _keyStruct.NSquare);

            // if we use simple key generation (g = n + 1), we can use
            // (n+1)^m = n*m + 1  mod n^2
            var Gm = (_keyStruct.N * Encode(message) + 1) % _keyStruct.NSquare;
            var Gm_Neg = (_keyStruct.N * Encode(-message) + 1) % _keyStruct.NSquare;

            var C = (Gm * RN) % _keyStruct.NSquare;
            var C_Neg = (Gm_Neg * RN) % _keyStruct.NSquare;

            var lgth = res.Length >> 1;
            C.TryWriteBytes(res.Slice(0, lgth), out _);
            C_Neg.TryWriteBytes(res.Slice(lgth, lgth), out _);
        }

        private BigInteger Encode(BigFraction a)
        {
            if (a < 0)
                a = a + PaillierKeyStruct.MaxRawPlaintext + BigInteger.One;
            a *= PaillierKeyStruct.PlaintextExp;
            return a.ToBigInteger();
        }

        public void Dispose()
        {
            rng.Dispose();
        }
    }
}
