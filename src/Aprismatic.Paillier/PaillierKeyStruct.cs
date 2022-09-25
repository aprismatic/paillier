using System.Numerics;

namespace Aprismatic.Paillier
{
    public struct PaillierKeyDefaults
    {
        public const int DefaultMaxPlaintextBits = 128;
        public const int DefaultPlaintextDecPlace = 12;
    }

    public struct PaillierKeyStruct
    {
        // PUBLIC KEY
        public readonly BigInteger N;
        public readonly BigInteger G;
        public readonly int MaxPlaintextBits;
        public readonly int PlaintextDecPlace; // decimal places allowed in plain text

        // PRIVATE KEY
        public readonly BigInteger Lambda;
        public readonly BigInteger Mu;

        // CONSTRUCTOR
        public PaillierKeyStruct(BigInteger n, BigInteger g, BigInteger lambda, BigInteger mu, int maxptbits, int ptdecplaces)
        {
            N = n;
            NSquare = n * n;
            NBitCount = n.BitCount();
            NLength = (NBitCount + 7) >> 3; // div 8
            NSquareLength = NLength * 2;

            G = g;

            MaxPlaintextBits = maxptbits;
            PlaintextDecPlace = ptdecplaces;

            PlaintextExp = BigInteger.Pow(10, PlaintextDecPlace);
            MaxRawPlaintext = BigInteger.Pow(2, MaxPlaintextBits) - BigInteger.One;
            MaxEncryptableValue = MaxRawPlaintext >> 1;

            MaxRawPlaintextPlusOneTimesExp = (MaxRawPlaintext + BigInteger.One) * PlaintextExp;
            MaxEncryptableValueTimesExp = MaxEncryptableValue * PlaintextExp;

            Lambda = lambda;

            Mu = mu;

            CiphertextBlocksize = NLength * 2 + 2;      // We add 2 because last bit of a BigInteger is reserved to store its sign.
            CiphertextLength = CiphertextBlocksize * 2; // Therefore, theoretically, each part of ciphertext might need an extra byte to hold that one bit
        }

        // HELPER VALUES
        // These values are derived from the pub/priv key and precomputed for faster processing
        public readonly BigInteger PlaintextExp;

        public readonly BigInteger MaxRawPlaintext;
        public readonly BigInteger MaxRawPlaintextPlusOneTimesExp;

        public readonly BigInteger MaxEncryptableValue;
        public readonly BigInteger MaxEncryptableValueTimesExp;

        public readonly int NBitCount;
        public readonly int NLength;
        public readonly BigInteger NSquare;
        public readonly int NSquareLength;

        public readonly int CiphertextBlocksize;
        public readonly int CiphertextLength;

        public PaillierParameters ExportParameters(bool includePrivateParams)
        {
            var prms = new PaillierParameters
            {
                N = N.ToByteArray(),
                G = G.ToByteArray(),
                MaxPlaintextBits = MaxPlaintextBits,
                PlaintextDecPlace = PlaintextDecPlace
            };

            // if required, include the private key values Lambda and Mu
            if (includePrivateParams)
            {
                prms.Lambda = Lambda.ToByteArray();
                prms.Mu = Mu.ToByteArray();
            }
            else
            {
                // ensure that we zero the value
                prms.Lambda = BigInteger.Zero.ToByteArray();
                prms.Mu = BigInteger.Zero.ToByteArray();
            }

            return prms;
        }
    }
}
