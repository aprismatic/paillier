/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.
 
 This library is provided as-is and is covered by the MIT License [1].
  
 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;
using System.Security.Cryptography;
using System.Numerics;
using BigIntegerExt;


namespace PaillierExt
{
    public class PaillierEncryptor : PaillierAbstractCipher, IDisposable
    {
        private RNGCryptoServiceProvider o_random;

        public PaillierEncryptor(PaillierKeyStruct p_struct)
            : base(p_struct)
        {
            o_random = new RNGCryptoServiceProvider();
        }

        // TODO: check again for encryption
        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            // generate random R
            var R = new BigInteger();
            R = R.GenRandomBits(o_key_struct.N.BitCount() - 1, o_random); // R's bitlength is n-1 so that r is within Zn


            // ciphertext c = g^m * r^n mod n^2
            var Nsquare = o_key_struct.N * o_key_struct.N;
            var C = (BigInteger.ModPow(o_key_struct.G, new BigInteger(p_block), Nsquare)
                           * BigInteger.ModPow(R, o_key_struct.N, Nsquare)) % Nsquare;



            // create an array to contain the ciphertext
            var x_result = new byte[o_ciphertext_blocksize + 2];
            var c_bytes = C.ToByteArray();

            // copy c_bytes into x_result
            Array.Copy(c_bytes, 0, x_result, 0, c_bytes.Length);
            // return result array
            return x_result;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            return (p_final_block.Length > 0) ? ProcessDataBlock(PadPlaintextBlock(p_final_block)) : new byte[0];
        }

        protected byte[] PadPlaintextBlock(byte[] p_block)
        {
            if (p_block.Length < o_block_size)
            {
                var x_padded = new byte[o_block_size];

                switch (o_key_struct.Padding)
                {
                    // trailing zeros
                    case PaillierPaddingMode.TrailingZeros:
                        Array.Copy(p_block, 0, x_padded, 0, p_block.Length);
                        break;

                    case PaillierPaddingMode.LeadingZeros:
                        Array.Copy(p_block, 0, x_padded, o_block_size - p_block.Length, p_block.Length);
                        break;

                    case PaillierPaddingMode.ANSIX923:
                        throw new NotImplementedException();
                        break;

                    case PaillierPaddingMode.BigIntegerPadding:
                        Array.Copy(p_block, 0, x_padded, 0, p_block.Length);
                        if ((p_block[p_block.Length - 1] & 0b1000_0000) == 1)
                        {
                            for (var i = p_block.Length; i < x_padded.Length; i++)
                            {
                                x_padded[i] = 0xFF;
                            }
                        }
                        break;

                    default:
                        throw new ArgumentOutOfRangeException();
                }

                return x_padded;
            }

            return p_block;
        }

        public void Dispose()
        {
            o_random.Dispose();
        }
    }
}
