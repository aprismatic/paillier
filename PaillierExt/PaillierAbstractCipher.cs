/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.

 This library is provided as-is and is covered by the MIT License [1].

 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;
using System.IO;
using System.Numerics;

namespace PaillierExtModified
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

    }
}
