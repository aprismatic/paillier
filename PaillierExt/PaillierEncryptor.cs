/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.
 
 This library is provided as-is and is covered by the MIT License [1].
  
 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;

namespace PaillierExt
{
    public class PaillierEncryptor : PaillierAbstractCipher
    {
        Random o_random;

        public PaillierEncryptor(PaillierKeyStruct p_struct)
            : base(p_struct)    // this base keyword means the constructor will use the base's constructor -TA
        {
            o_random = new Random();
        }

        // TODO: check again for encryption
        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            //// set random K
            //BigInteger K;
            //do
            //{
            //    K = new BigInteger();
            //    K.genRandomBits(o_key_struct.P.bitCount() - 1, o_random);
            //} while (K.gcd(o_key_struct.P - 1) != 1);

            //// compute the values A and B
            //BigInteger A = o_key_struct.G.modPow(K, o_key_struct.P);
            //BigInteger B = (o_key_struct.Y.modPow(K, o_key_struct.P) * new BigInteger(p_block)) % (o_key_struct.P);

            //// create an array to contain the ciphertext
            //byte[] x_result = new byte[o_ciphertext_blocksize];
            //// copy the bytes from A and B into the result array
            //byte[] x_a_bytes = A.getBytes();
            //Array.Copy(x_a_bytes, 0, x_result, o_ciphertext_blocksize / 2
            //    - x_a_bytes.Length, x_a_bytes.Length);
            //byte[] x_b_bytes = B.getBytes();
            //Array.Copy(x_b_bytes, 0, x_result, o_ciphertext_blocksize
            //    - x_b_bytes.Length, x_b_bytes.Length);
            //// return the result array
            //return x_result;

            // *********** SPECIAL ************ //

            // generate random R
            BigInteger R = new BigInteger();
            R.genRandomBits(o_key_struct.N.bitCount() - 1, o_random); //R's bitlength is n-1 so that r is within Zn

            // ciphertext c = g^m * r^n mod n^2
            BigInteger Nsquare = o_key_struct.N * o_key_struct.N;
            BigInteger C = (o_key_struct.G.modPow(new BigInteger(p_block), Nsquare)
                           * R.modPow(o_key_struct.N, Nsquare)) % Nsquare;

            // create an array to contain the ciphertext
            byte[] x_result = new byte[o_ciphertext_blocksize];
            byte[] c_bytes = C.getBytes();

            // copy c_bytes into x_result
            Array.Copy(c_bytes, 0, x_result, o_ciphertext_blocksize - c_bytes.Length, c_bytes.Length);

            // return result array
            return x_result;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            if (!(p_final_block.Length > 0))
                return new byte[0];     //return empty block

            // ***************** SPECIAL ******************* //
            return ProcessDataBlock(PadPlaintextBlock(p_final_block));
        }

        // ****** also special ******* //
        protected byte[] PadPlaintextBlock(byte[] p_block)
        {
            if (p_block.Length < o_block_size)
            {
                byte[] x_padded = new byte[o_block_size];

                switch (o_key_struct.Padding)
                {
                    // trailing zeros
                    case PaillierPaddingMode.Zeros:
                        Array.Copy(p_block, 0, x_padded, 0, p_block.Length);
                        break;

                    case PaillierPaddingMode.LeadingZeros:
                        Array.Copy(p_block, 0, x_padded, o_block_size - p_block.Length, p_block.Length);
                        break;

                    case PaillierPaddingMode.ANSIX923:
                        throw new System.NotImplementedException();
                        break;
                }

                return x_padded;
            }

            return p_block;
        }
    }
}
