using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PaillierExt
{
    public struct PaillierKeyStruct
    {
        public BigInteger N;
        public BigInteger G;
        public BigInteger Lambda;
        public BigInteger Miu;
        public PaillierPaddingMode Padding; // this parameter should be considered part of the public key

        // ******************** SPECIAL ************* //
        public int getPlaintextBlocksize()
        {
            return (N.bitCount() - 1) / 8;
        }

        // TODO: check again ciphertext and plaintext block size
        public int getCiphertextBlocksize()
        {
            return ((N.bitCount() + 7) / 8) * 2;
        }
    }
}
