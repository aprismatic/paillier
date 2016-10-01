/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.
 
 This library is provided as-is and is covered by the MIT License [1].
  
 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;
using System.Linq;

namespace PaillierExt
{
    public class PaillierDecryptor : PaillierAbstractCipher
    {
        public PaillierDecryptor(PaillierKeyStruct p_struct)
            : base(p_struct)
        {
            // set the default block size to be ciphertext
            o_block_size = o_ciphertext_blocksize;
        }

        //TODO: check again for decryption
        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            var block = new BigInteger(p_block);

            // calculate M
            // c array is in nsquare bytes
            // m = (c^lambda(mod nsquare) - 1) / n * miu (mod n)
            var m = (block.modPow(o_key_struct.Lambda, o_key_struct.N * o_key_struct.N) - 1) /
                            o_key_struct.N * o_key_struct.Miu % o_key_struct.N;
            var x_m_bytes = m.getBytes();

            // we may end up with results which are short some leading
            // bytes - add these are required 
            if (x_m_bytes.Length < o_plaintext_blocksize)
            {
                var x_full_result = new byte[o_plaintext_blocksize];
                Array.Copy(x_m_bytes, 0, x_full_result,
                    o_plaintext_blocksize - x_m_bytes.Length, x_m_bytes.Length);
                x_m_bytes = x_full_result;
            }

            return x_m_bytes;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            if (!(p_final_block.Length > 0))
            {
                return new byte[0];
            }

            return UnpadPlaintextBlock(ProcessDataBlock(p_final_block));
        }

        protected byte[] UnpadPlaintextBlock(byte[] p_block)
        {
            var x_res = new byte[0];

            switch (o_key_struct.Padding)
            {
                // removing all the leading zeros
                case PaillierPaddingMode.LeadingZeros:
                    var i = 0;
                    for (; i < o_plaintext_blocksize; i++)
                    {
                        if (p_block[i] != 0)
                            break;
                    }
                    x_res = p_block.Skip(i).ToArray(); // TODO: Consider rewriting
                    break;

                // we can't determine which bytes are padding and which are meaningful
                // thus we return the block as is
                case PaillierPaddingMode.Zeros:
                    x_res = p_block;
                    break;

                case PaillierPaddingMode.ANSIX923:
                    throw new NotImplementedException();

                // unlikely to happen
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return x_res;
        }
    }
}
