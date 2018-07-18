/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.

 This library is provided as-is and is covered by the MIT License [1].

 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System.Numerics;
using BigIntegerExt;

namespace PaillierExtModified
{
    public struct PaillierKeyStruct
    {
        private BigInteger _n;

        public BigInteger N
        {
            get => _n;
            set
            {
                _n = value;
                NSquare = _n * _n;
            }
        }
        public BigInteger NSquare { get; private set; }

        public BigInteger G;
        public BigInteger Lambda;
        public BigInteger Miu;
        //public PaillierPaddingMode Padding; // this parameter should be considered part of the public key


        public int getPlaintextBlocksize()
        {
            return (_n.BitCount() - 1) / 8;
        }

        // TODO: check again ciphertext and plaintext block size
        public int getCiphertextBlocksize()
        {
            return ((_n.BitCount() + 7) / 8) * 2 + 2;
        }
    }
}
