/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.

 This library is provided as-is and is covered by the MIT License [1].

 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;
using System.IO;

namespace PaillierExt
{
    public abstract class PaillierAbstractCipher
    {
        protected int o_block_size;
        protected int o_plaintext_blocksize;
        protected int o_ciphertext_blocksize;
        protected PaillierKeyStruct o_key_struct;

        public PaillierAbstractCipher(PaillierKeyStruct p_key_struct)
        {
            o_key_struct = p_key_struct;

            o_plaintext_blocksize = p_key_struct.getPlaintextBlocksize();
            o_ciphertext_blocksize = p_key_struct.getCiphertextBlocksize();

            o_block_size = o_plaintext_blocksize;
        }

        public byte[] ProcessData(byte[] p_data)
        {
            var x_complete_blocks = p_data.Length / o_block_size + (p_data.Length % o_block_size > 0 ? 1 : 0);
            x_complete_blocks = Math.Max(x_complete_blocks - 1, 0);

            if (x_complete_blocks == 0)
                return ProcessFinalDataBlock(p_data);

            using (var x_stream = new MemoryStream())
            {
                var x_block = new byte[o_block_size];

                var i = 0;
                for (; i < x_complete_blocks; i++)
                {
                    Array.Copy(p_data, i * o_block_size, x_block, 0, o_block_size);

                    var x_result = ProcessDataBlock(x_block);

                    x_stream.Write(x_result, 0, x_result.Length);
                }

                var x_final_block = new byte[p_data.Length - (x_complete_blocks * o_block_size)];
                Array.Copy(p_data, i * o_block_size, x_final_block, 0, x_final_block.Length);

                var x_final_result = ProcessFinalDataBlock(x_final_block);

                x_stream.Write(x_final_result, 0, x_final_result.Length);

                return x_stream.ToArray();
            }
        }

        protected abstract byte[] ProcessDataBlock(byte[] p_block);

        protected abstract byte[] ProcessFinalDataBlock(byte[] p_final_block);
    }
}
