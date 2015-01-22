using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PaillierExt
{
    public class PaillierDecryptor:PaillierAbstractCipher
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
            //// extract the byte arrays that represent A and B
            //byte[] x_a_bytes = new byte[o_ciphertext_blocksize / 2];
            //Array.Copy(p_block, 0, x_a_bytes, 0, x_a_bytes.Length);
            //byte[] x_b_bytes = new byte[o_ciphertext_blocksize / 2];
            //Array.Copy(p_block, x_a_bytes.Length, x_b_bytes, 0, x_b_bytes.Length);

            //// create big integers from the byte arrays
            //BigInteger A = new BigInteger(x_a_bytes);
            //BigInteger B = new BigInteger(x_b_bytes);

            //// calculate the value M
            //BigInteger M = (B * A.modPow(o_key_struct.X, o_key_struct.P).modInverse(o_key_struct.P)) % o_key_struct.P;

            //// return the result - take care to ensure that we create
            //// a result which is the correct length
            //byte[] x_m_bytes = M.getBytes();

            //// we may end up with results which are short some leading
            //// bytes - add these are required
            //if (x_m_bytes.Length < o_plaintext_blocksize)
            //{
            //    byte[] x_full_result = new byte[o_plaintext_blocksize];
            //    Array.Copy(x_m_bytes, 0, x_full_result,
            //        o_plaintext_blocksize - x_m_bytes.Length, x_m_bytes.Length);
            //    x_m_bytes = x_full_result;
            //}
            //return x_m_bytes;


            // convert byte array to BigInteger
            BigInteger C = new BigInteger(p_block);

            // calculate M
            // c array is in nsquare bytes
            // m = (c^lambda(mod nsquare) - 1) / n * miu (mod n)
            BigInteger M = (C.modPow(o_key_struct.Lambda, o_key_struct.N * o_key_struct.N) - 1) /
                            o_key_struct.N * o_key_struct.Miu % o_key_struct.N;
            byte[] x_m_bytes = M.getBytes();

            // we may end up with results which are short some leading
            // bytes - add these are required 
            if (x_m_bytes.Length < o_plaintext_blocksize)
            {
                byte[] x_full_result = new byte[o_plaintext_blocksize];
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

            // ************ SPECIAL ************* //
            return UnpadPlaintextBlock(ProcessDataBlock(p_final_block));
        }

        protected byte[] UnpadPlaintextBlock(byte[] p_block)
        {
            byte[] x_res = new byte[0];

            switch (o_key_struct.Padding)
            {
                // removing all the leading zeros
                case PaillierPaddingMode.LeadingZeros:
                    int i = 0;
                    for (; i < o_plaintext_blocksize; i++)
                    {
                        if (p_block[i] != 0)
                            break;
                    }
                    x_res = p_block.Skip(i).ToArray();
                    break;

                // we can't determine which bytes are padding and which are meaningful
                // thus we return the block as is
                case PaillierPaddingMode.Zeros:
                    x_res = p_block;
                    break;

                case PaillierPaddingMode.ANSIX923:
                    throw new System.NotImplementedException();
                    break;

                // unlikely to happen
                default:
                    throw new System.ArgumentOutOfRangeException();
                    break;
            }

            return x_res;
        }
    }
}
