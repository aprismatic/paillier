using System;
using System.Security.Cryptography;
using System.Numerics;
using Aprismatic.PaillierExt.Homomorphism;

namespace Aprismatic.PaillierExt
{
    public class Paillier : AsymmetricAlgorithm, IDisposable
    {
        private readonly PaillierKeyStruct keyStruct;
        private readonly PaillierEncryptor encryptor;
        private readonly PaillierDecryptor decryptor;

        public int MaxPlaintextBits => keyStruct.MaxPlaintextBits;
        public BigInteger MaxEncryptableValue => keyStruct.MaxEncryptableValue;
        public BigInteger PlaintextExp => keyStruct.PlaintextExp;
        public int PlaintextDecPlace => keyStruct.PlaintextDecPlace;
        public int CiphertextLength => keyStruct.CiphertextLength;
        public BigInteger NSquare => keyStruct.NSquare;
        public int NSquareLength => keyStruct.NSquareLength;

        public Paillier(int keySize) // TODO: Constructor should probably optionally accept an RNG
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
            KeySizeValue = keySize;
            keyStruct = CreateKeyPair(PaillierKeyDefaults.DefaultMaxPlaintextBits, PaillierKeyDefaults.DefaultPlaintextDecPlace);
            encryptor = new PaillierEncryptor(keyStruct);
            decryptor = new PaillierDecryptor(keyStruct);
        }

        public Paillier(PaillierParameters prms) // TODO: Consolidate constructors in one method
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            keyStruct = new PaillierKeyStruct(
                new BigInteger(prms.N),
                new BigInteger(prms.G),
                (prms.Lambda?.Length ?? 0) > 0 ? new BigInteger(prms.Lambda) : BigInteger.Zero,
                (prms.Mu?.Length ?? 0) > 0 ? new BigInteger(prms.Mu) : BigInteger.Zero,
                prms.MaxPlaintextBits,
                prms.PlaintextDecPlace
            );

            KeySizeValue = keyStruct.NLength * 8; // TODO: Validate that key is of legal size

            encryptor = new PaillierEncryptor(keyStruct);
            decryptor = new PaillierDecryptor(keyStruct);
        }

        public Paillier(string Xml) : this(PaillierParameters.FromXml(Xml))
        { }

        private PaillierKeyStruct CreateKeyPair(int maxptbits, int ptdecplaces) // TODO: This method should probably move to KeyStruct
        {
            BigInteger N, Lambda, G, Mu;

            // create the large prime number, p and q
            // p and q are assumed to have the same bit length (e.g., 192 bit each, so that N is 384)
            // if N length is not the same to keySize, will regenerate p and q which will make a new N
            using var rng = RandomNumberGenerator.Create();
            var p = new BigInteger();
            var q = new BigInteger();
            var halfKeyStrength = KeySizeValue >> 1; // div 2
            do
            {
                p = p.GenPseudoPrime(halfKeyStrength, 16, rng);
                q = q.GenPseudoPrime(halfKeyStrength, 16, rng);

                N = p * q;
            } while (N.BitCount() < KeySizeValue - 7);

            // compute G
            //  First option:  G is random in Z*(N^2)
            //  Second option: G = N + 1
            G = N + BigInteger.One;

            // compute lambda
            //  lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
            //  or simpler variant, lambda = (p-1)(q-1), since p and q have same length
            Lambda = (p - BigInteger.One) * (q - BigInteger.One);

            // Mu = (L(g^lambda mod NSq))^-1 mod n
            // or simple: Mu = lambda^-1 (mod n)
            Mu = Lambda.ModInverse(N);

            return new PaillierKeyStruct(N, G, Lambda, Mu, maxptbits, ptdecplaces);
        }

        public byte[] EncryptData(BigFraction message)
        {
            var res = new byte[keyStruct.CiphertextBlocksize * 2];
            encryptor.ProcessBigInteger(message, res.AsSpan());
            return res;
        }

        public BigFraction DecryptData(byte[] p_data)
        {
            return decryptor.ProcessByteBlock(p_data);
        }

        public byte[] Add(byte[] first, byte[] second)
        {
            return PaillierHomomorphism.Add(first, second, keyStruct.NSquare.ToByteArray());
        }

        public byte[] Subtract(byte[] first, byte[] second)
        {
            return PaillierHomomorphism.Subtract(first, second, keyStruct.NSquare.ToByteArray());
        }

        public PaillierParameters ExportParameters(bool includePrivateParams) => keyStruct.ExportParameters(includePrivateParams);

        public override string ToXmlString(bool includePrivateParameters)
        {
            var prms = ExportParameters(includePrivateParameters);
            return prms.ToXml(includePrivateParameters);
        }

        public new void Dispose() => encryptor.Dispose();
    }
}
