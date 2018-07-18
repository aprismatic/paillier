/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.

 This library is provided as-is and is covered by the MIT License [1].

 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using BigIntegerExt;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace PaillierExtModified
{
    public class PaillierEncryptor : PaillierAbstractCipher, IDisposable
    {
        private RandomNumberGenerator o_random;

        public PaillierEncryptor(PaillierKeyStruct p_struct)
            : base(p_struct)
        {
            o_random = RandomNumberGenerator.Create();
        }

        public byte[] ProcessBlockBigInteger(BigInteger p_block)
        {
            // generate random R
            var R = new BigInteger();
            R = R.GenRandomBits(o_key_struct.N.BitCount() - 1, o_random); // R's bitlength is n-1 so that r is within Zn

            // ciphertext c = g^m * r^n mod n^2
            var Gm = BigInteger.ModPow(o_key_struct.G, p_block, o_key_struct.NSquare);
            var RN = BigInteger.ModPow(R, o_key_struct.N, o_key_struct.NSquare);

            var C = (Gm * RN) % o_key_struct.NSquare;

            var x_result = new byte[o_ciphertext_blocksize];
            var c_bytes = C.ToByteArray();

            Array.Copy(c_bytes, 0, x_result, 0, c_bytes.Length);

            return x_result;
        }

        public void Dispose()
        {
            o_random.Dispose();
        }
    }
}
