using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic.BigFraction;
using Aprismatic.BigIntegerExt;

namespace PaillierExt
{
    public class PaillierEncryptor : PaillierAbstractCipher, IDisposable
    {
        private RandomNumberGenerator rng;

        public PaillierEncryptor(PaillierKeyStruct keyStruct)
            : base(keyStruct)
        {
            rng = RandomNumberGenerator.Create();
        }

        public byte[] ProcessBigInteger(BigFraction message)
        {
            if (BigInteger.Abs(message.Numerator) > KeyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Numerator to encrypt is too large. Message should be |m| < 2^{KeyStruct.getMaxPlaintextBits() - 1}");

            if (message.Denominator > KeyStruct.PlaintextExp)
                throw new ArgumentException($"Denominator to encrypt is too large. Denominator should be <= {KeyStruct.PlaintextExp}");

            // generate random R
            var R = new BigInteger();
            R = R.GenRandomBits(KeyStruct.N.BitCount() - 1, rng); // R's bitlength is n-1 so that r is within Zn

            // ciphertext c = g^m * r^n mod n^2
            var RN = BigInteger.ModPow(R, KeyStruct.N, KeyStruct.NSquare);

            // if we use simple key generation (g = n + 1), we can use
            // (n+1)^m = n*m + 1  mod n^2
            var Gm = (KeyStruct.N * Encode(message) + 1) % KeyStruct.NSquare;

            var C = (Gm * RN) % KeyStruct.NSquare;

            var res = new byte[CiphertextBlocksize];
            var c_bytes = C.ToByteArray();

            Array.Copy(c_bytes, 0, res, 0, c_bytes.Length);

            return res;
        }

        private BigInteger Encode(BigFraction a)
        {
            if (a < 0)
                a = a + KeyStruct.MaxRawPlaintext + 1;
            a = a * KeyStruct.PlaintextExp;
            return a.ToBigInteger();
        }

        public void Dispose()
        {
            rng.Dispose();
        }
    }
}
