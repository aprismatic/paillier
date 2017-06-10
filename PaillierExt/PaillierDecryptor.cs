/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.
 
 This library is provided as-is and is covered by the MIT License [1].
  
 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;
using System.Linq;
using System.Numerics;

namespace PaillierExt
{
    public class PaillierDecryptor : PaillierAbstractCipher
    {
        public PaillierDecryptor(PaillierKeyStruct p_struct)
            : base(p_struct)
        {
            // set the default block size to be ciphertext
            o_block_size = o_ciphertext_blocksize + 2;
        }

        //TODO: check again for decryption
        protected override byte[] ProcessDataBlock(byte[] p_block)
        {
            var block = new BigInteger(p_block);


            // calculate M
            // c array is in nsquare bytes
            // m = (c^lambda(mod nsquare) - 1) / n * miu (mod n)
            var m = (BigInteger.ModPow(block, o_key_struct.Lambda, o_key_struct.N * o_key_struct.N) - 1) /
                            o_key_struct.N * o_key_struct.Miu % o_key_struct.N;
            var x_m_bytes = m.ToByteArray();

            // we may end up with results which are short some leading
            // bytes - add these are required 
            if (x_m_bytes.Length < o_plaintext_blocksize)
            {
                var x_full_result = new byte[o_plaintext_blocksize];
                Array.Copy(x_m_bytes, 0, x_full_result, 0, x_m_bytes.Length);
                x_m_bytes = x_full_result;
            }


            return x_m_bytes;
        }

        protected override byte[] ProcessFinalDataBlock(byte[] p_final_block)
        {
            return p_final_block.Length > 0 ? UnpadPlaintextBlock(ProcessDataBlock(p_final_block)) : new byte[0];
        }

        protected byte[] UnpadPlaintextBlock(byte[] p_block)
        {
            var x_res = new byte[0];

            switch (o_key_struct.Padding)
            {
                // removing all the leading zeros
                case PaillierPaddingMode.LeadingZeros:
                    var i = 0;
                    for (; i < p_block.Length; i++)
                    {
                        if (p_block[i] != 0)
                            break;
                    }
                    x_res = p_block.Skip(i).ToArray(); // TODO: Consider rewriting
                    break;

                // we can't determine which bytes are padding and which are meaningful
                // thus we return the block as is
                case PaillierPaddingMode.TrailingZeros:
                    var j = p_block.Length - 1;
                    for (; j >= 0; j--)
                    {
                        if (p_block[j] != 0)
                            break;
                    }
                    x_res = p_block.Take(j + 1).ToArray();
                    break;

                case PaillierPaddingMode.ANSIX923:
                    throw new NotImplementedException();
                    break;

                case PaillierPaddingMode.BigIntegerPadding:
                    var k = p_block.Length - 1;

                    if (p_block[k] == 0xFF)
                    {
                        for (; k >= 0; k--)
                        {
                            if (p_block[k] != 0xFF)
                            {
                                if (k > 0)
                                {
                                    if ((p_block[k] & 0b1000_0000) == 0)
                                        k++;
                                }
                                break;
                            }
                        }
                    }
                    else if (p_block[k] == 0)
                    {
                        for (; k >= 0; k--)
                        {
                            if (p_block[k] != 0)
                            {
                                if (k > 0)
                                {
                                    if ((p_block[k] & 0b1000_0000) != 0)
                                        k++;
                                }
                                break;
                            }
                        }
                    }
                    x_res = p_block.Take(k + 1).ToArray();
                    break;

                // unlikely to happen
                default:
                    throw new ArgumentOutOfRangeException();
            }

            return x_res;
        }
    }
}
