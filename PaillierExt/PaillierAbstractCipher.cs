using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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
            // set the key details
            o_key_struct = p_key_struct;

            // calculate the blocksizes
            o_plaintext_blocksize = p_key_struct.getPlaintextBlocksize();
            o_ciphertext_blocksize = p_key_struct.getCiphertextBlocksize();

            // set the default block for plaintext, which is suitable for encryption
            o_block_size = o_plaintext_blocksize;
        }

         public byte[] ProcessData(byte[] p_data)
         {
             // create a stream backed by a memory array
             MemoryStream x_stream = new MemoryStream();

             // determine how many complete blocks there are
             int x_complete_blocks = p_data.Length / o_block_size;

             // create an array which will hold a block
             byte[] x_block = new Byte[o_block_size];

             // run through and process the complete blocks
             int i = 0;
             for (; i < x_complete_blocks; i++)
             {
                 // copy the block and create the big integer
                 Array.Copy(p_data, i * o_block_size, x_block, 0, o_block_size);
                 // process the block
                 byte[] x_result = ProcessDataBlock(x_block);
                 // write the processed data into the stream
                 x_stream.Write(x_result, 0, x_result.Length);
             }

             // process the final block
             byte[] x_final_block = new Byte[p_data.Length -
                 (x_complete_blocks * o_block_size)];
             Array.Copy(p_data, i * o_block_size, x_final_block, 0,
                 x_final_block.Length);

             // process the final block
             byte[] x_final_result = ProcessFinalDataBlock(x_final_block);

             // write the final data bytes into the stream
             x_stream.Write(x_final_result, 0, x_final_result.Length);

             // return the contents of the stream as a byte array
             return x_stream.ToArray();
         }

         protected abstract byte[] ProcessDataBlock(byte[] p_block);

         protected abstract byte[] ProcessFinalDataBlock(byte[] p_final_block);     

    }
}
