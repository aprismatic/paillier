/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.
 
 This library is provided as-is and is covered by the MIT License [1].
  
 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/
using System.Numerics;
using BigIntegerExt;

namespace PaillierExt
{
    public struct PaillierKeyStruct
    {
        public BigInteger N;
        public BigInteger G;
        public BigInteger Lambda;
        public BigInteger Miu;
        public PaillierPaddingMode Padding; // this parameter should be considered part of the public key

        public int getPlaintextBlocksize()
        {
            return (N.BitCount() - 1) / 8;
        }

        // TODO: check again ciphertext and plaintext block size
        public int getCiphertextBlocksize()
        {
            return ((N.BitCount() + 7) / 8) * 2;
        }
    }
}
