using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Aprismatic.PaillierExt
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
            if (message.Denominator > KeyStruct.PlaintextExp)
            {
                BigInteger denominator = KeyStruct.PlaintextExp;
                BigInteger numerator = message.Numerator * denominator / message.Denominator;
                message = new BigFraction(denominator, numerator);
            }

            if (BigInteger.Abs(message.Numerator) > KeyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Numerator to encrypt is too large. Message should be |m| < 2^{KeyStruct.getMaxPlaintextBits() - 1}");

            // generate random R
            var R = new BigInteger();
            R = R.GenRandomBits(KeyStruct.N.BitCount() - 1, rng); // R's bitlength is n-1 so that r is within Zn

            // ciphertext c = g^m * r^n mod n^2
            var RN = BigInteger.ModPow(R, KeyStruct.N, KeyStruct.NSquare);

            // if we use simple key generation (g = n + 1), we can use
            // (n+1)^m = n*m + 1  mod n^2
            var Gm = (KeyStruct.N * Encode(message) + 1) % KeyStruct.NSquare;
            var Gm_Neg = (KeyStruct.N * Encode(-message) + 1) % KeyStruct.NSquare;

            var C = (Gm * RN) % KeyStruct.NSquare;
            var C_Neg = (Gm_Neg * RN) % KeyStruct.NSquare;

            var res = new byte[CiphertextBlocksize * 2];
            var c_bytes = C.ToByteArray();
            var c_Neg_bytes = C_Neg.ToByteArray();

            Array.Copy(c_bytes, 0, res, 0, c_bytes.Length);
            Array.Copy(c_Neg_bytes, 0, res, CiphertextBlocksize, c_Neg_bytes.Length);

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
