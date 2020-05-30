using System.Numerics;

namespace Aprismatic.PaillierExt
{
    public struct PaillierKeyStruct
    {
        public readonly BigInteger N;
        public readonly BigInteger G;
        public readonly BigInteger Lambda;
        public readonly BigInteger Miu;

        public PaillierKeyStruct(BigInteger n, BigInteger g, BigInteger lambda, BigInteger miu)
        {
            N = n;
            NSquare = n * n;
            NBitCount = n.BitCount();
            NLength = (NBitCount + 7) >> 3; // div 8
            NSquareLength = NLength * 2;

            G = g;

            Lambda = lambda;

            Miu = miu;

            CiphertextBlocksize = NLength * 2 + 2;      // We add 2 because last bit of a BigInteger is reserved to store its sign.
            CiphertextLength = CiphertextBlocksize * 2; // Therefore, theoretically, each part of ciphertext might need an extra byte to hold that one bit
        }

        public const int MaxPlaintextBits = 128;
        public const int PlaintextDecPlace = 12; // 12 decimal places allowed in plain text
        public static readonly BigInteger PlaintextExp = BigInteger.Pow(10, PlaintextDecPlace);

        public static readonly BigInteger MaxRawPlaintext = BigInteger.Pow(2, MaxPlaintextBits) - BigInteger.One;
        public static readonly BigInteger MaxEncryptableValue = MaxRawPlaintext >> 1;

        public readonly int NBitCount;
        public readonly int NLength;
        public readonly BigInteger NSquare;
        public readonly int NSquareLength;

        public readonly int CiphertextBlocksize;
        public readonly int CiphertextLength;
    }
}
