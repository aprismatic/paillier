using System;
using System.Linq;
using System.Security.Cryptography;
using System.Numerics;
using Aprismatic.Paillier.Homomorphism;

namespace Aprismatic.Paillier
{
    public class Paillier : AsymmetricAlgorithm, IDisposable
    {
        private readonly PaillierKeyStruct keyStruct;

        public readonly PaillierEncryptor Encryptor;
        public readonly PaillierDecryptor Decryptor;

        public int MaxPlaintextBits => keyStruct.MaxPlaintextBits;
        public BigInteger MaxEncryptableValue => keyStruct.MaxEncryptableValue;
        public BigInteger PlaintextExp => keyStruct.PlaintextExp;
        public int PlaintextDecPlace => keyStruct.PlaintextDecPlace;
        public BigInteger NSquare => keyStruct.NSquare;
        public int NSquareLength => keyStruct.NSquareLength;
        public int CiphertextLength => keyStruct.CiphertextLength;

        #region Constructors & Key Generation
        // TODO: Constructors should allow to specify MaxPlaintextBits and PlaintextDecPlace
        public Paillier(int keySize) // TODO: Constructor should probably optionally accept an RNG
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            KeySizeValue = keySize;
            if (!LegalKeySizesValue.Any(x => x.MinSize <= KeySizeValue && KeySizeValue <= x.MaxSize && (KeySizeValue - x.MinSize) % x.SkipSize == 0))
                throw new ArgumentException("Key size is not supported by this algorithm.");

            var (p, q, N) = GenPaillierModulus(KeySizeValue);
            keyStruct = CreateKeyPair(PaillierKeyDefaults.DefaultMaxPlaintextBits, PaillierKeyDefaults.DefaultPlaintextDecPlace, p, q, N);

            Encryptor = new PaillierEncryptor(keyStruct);
            Decryptor = new PaillierDecryptor(keyStruct);
        }

        public Paillier(BigInteger p, BigInteger q)
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            var N = p * q;
            KeySizeValue = N.BitCount();

            if (!LegalKeySizesValue.Any(x => x.MinSize <= KeySizeValue && KeySizeValue <= x.MaxSize && (KeySizeValue - x.MinSize) % x.SkipSize == 0))
                throw new ArgumentException("Key size is not supported by this algorithm.");

            // TODO: do we need to check that p and q bit count is half of N bit count?

            keyStruct = CreateKeyPair(PaillierKeyDefaults.DefaultMaxPlaintextBits, PaillierKeyDefaults.DefaultPlaintextDecPlace, p, q, N);

            Encryptor = new PaillierEncryptor(keyStruct);
            Decryptor = new PaillierDecryptor(keyStruct);
        }

        public Paillier(PaillierParameters prms) // TODO: Consolidate constructors in one method
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            keyStruct = new PaillierKeyStruct(
                new BigInteger(prms.N),
                new BigInteger(prms.G),
                new BigInteger(prms.Lambda),
                new BigInteger(prms.Mu),
                prms.MaxPlaintextBits,
                prms.PlaintextDecPlace
            );

            KeySizeValue = keyStruct.NLength * 8;
            if (!LegalKeySizesValue.Any(x => x.MinSize <= KeySizeValue && KeySizeValue <= x.MaxSize && (KeySizeValue - x.MinSize) % x.SkipSize == 0))
                throw new ArgumentException("Key size is not supported by this algorithm.");

            Encryptor = new PaillierEncryptor(keyStruct);
            Decryptor = new PaillierDecryptor(keyStruct);
        }

        public Paillier(string Xml) : this(PaillierParameters.FromXml(Xml))
        { }

        private static PaillierKeyStruct CreateKeyPair(int maxptbits, int ptdecplaces, BigInteger p, BigInteger q, BigInteger N) // TODO: This method should probably move to KeyStruct
        {
            BigInteger Lambda, G, Mu;

            // compute G
            //  First option:  G is random in Z*(N²)
            //  Second option: G = N + 1
            G = N + BigInteger.One;

            // compute λ
            //  λ = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
            //  or simpler variant, λ = (p-1)(q-1), since p and q have same length
            Lambda = (p - BigInteger.One) * (q - BigInteger.One);

            // µ = (L(g^λ mod N²))⁻¹  mod N
            // or simple: µ = λ⁻¹  mod N
            Mu = Lambda.ModInverse(N);

            return new PaillierKeyStruct(N, G, Lambda, Mu, maxptbits, ptdecplaces);
        }

        // TODO: test this method as it becomes part of public API
        public static (BigInteger p, BigInteger q, BigInteger N) GenPaillierModulus(int keySize)
        {
            // create two large prime numbers, p and q
            // p and q are assumed to have the same bit length (e.g., 192 bit each, so that N is 384)
            // if N length is not the same to keySize, will regenerate p and q which will make a new N

            using var rng = RandomNumberGenerator.Create();

            BigInteger N, p, q;

            var halfKeyStrength = keySize >> 1; // div 2
            do
            {
                do p = BigInteger.One.GenPseudoPrime(halfKeyStrength, 16, rng);
                while (p.BitCount() != halfKeyStrength);

                do q = BigInteger.One.GenPseudoPrime(halfKeyStrength, 16, rng);
                while (q.BitCount() != halfKeyStrength);

                N = p * q;
            } while (N.BitCount() != keySize);

            return (p, q, N);
        }
        #endregion

        #region Encryption & Decryprtion
        public byte[] EncryptData(BigFraction message)
        {
            if (BigFraction.Abs(message) > keyStruct.MaxEncryptableValue)
                throw new ArgumentException($"Numerator to encrypt is too large. Message should be |m| < 2^{keyStruct.MaxPlaintextBits - 1}");

            var res = new byte[keyStruct.CiphertextBlocksize * 2];

            var encodedMsg = Encode(message);
            var encodedMsgNeg = Encode(-message);

            Encryptor.ProcessBigInteger(encodedMsg, encodedMsgNeg, res.AsSpan());

            return res;
        }

        public BigFraction DecryptData(byte[] p_data)
        {
            return Decode(Decryptor.ProcessByteBlock(p_data));
        }
        #endregion

        #region Homomorphic Properties
        public BigInteger Encode(BigFraction msg) // TODO: Add tests now that this method is public
        {
            if (msg.Sign == -1)
                msg = msg + keyStruct.MaxRawPlaintext + BigFraction.One;

            if (msg.Denominator > keyStruct.PlaintextExp)
            {
                var denominator = keyStruct.PlaintextExp;
                var numerator = (msg.Numerator * denominator) / msg.Denominator;
                msg = new BigFraction(numerator, denominator);
            }

            msg *= keyStruct.PlaintextExp;
            return msg.ToBigInteger();
        }

        public BigFraction Decode(BigInteger n) // TODO: Add tests now that this method is public
        {
            var a = new BigFraction(n, keyStruct.PlaintextExp);
            while (a > keyStruct.MaxEncryptableValue)
                a -= keyStruct.MaxRawPlaintext + BigFraction.One;
            return a;
        }

        public byte[] Add(byte[] first, byte[] second) => PaillierHomomorphism.Add(first, second, keyStruct.NSquare.ToByteArray());

        public byte[] Subtract(byte[] first, byte[] second) => PaillierHomomorphism.Subtract(first, second, keyStruct.NSquare.ToByteArray());

        // TODO: Extract this method to Paillier.Homomorphism
        public byte[] PlaintextAdd(byte[] first, BigFraction second)
        {
            var encoded = Encode(second);

            var Gk = BigInteger.ModPow(keyStruct.G, encoded, keyStruct.NSquare); // maybe can do regular pow here, but not sure if that's faster

            var pos = first[..keyStruct.CiphertextBlocksize];
            var neg = first[keyStruct.CiphertextBlocksize..];

            var posRes = (new BigInteger(pos) * Gk) % keyStruct.NSquare;
            var negRes = (new BigInteger(neg) * Gk) % keyStruct.NSquare;

            var res = new byte[keyStruct.CiphertextBlocksize * 2];
            posRes.ToByteArray().CopyTo(res, 0);
            negRes.ToByteArray().CopyTo(res, keyStruct.CiphertextBlocksize);

            return res;
        }

        // TODO: Add PlaintextSubtract

        // TODO: Extract this method to Paillier.Homomorphism
        public byte[] PlaintextMultiply(byte[] first, BigInteger second)
        {
            var pos = first[..keyStruct.CiphertextBlocksize];
            var neg = first[keyStruct.CiphertextBlocksize..];

            var posRes = BigInteger.ModPow(new BigInteger(pos), second, keyStruct.NSquare);
            var negRes = BigInteger.ModPow(new BigInteger(neg), second, keyStruct.NSquare);

            var res = new byte[keyStruct.CiphertextBlocksize * 2];
            posRes.ToByteArray().CopyTo(res, 0);
            negRes.ToByteArray().CopyTo(res, keyStruct.CiphertextBlocksize);

            return res;
        }
        #endregion

        #region Serialization
        public PaillierParameters ExportParameters(bool includePrivateParams) => keyStruct.ExportParameters(includePrivateParams);

        public override string ToXmlString(bool includePrivateParameters)
        {
            var prms = ExportParameters(includePrivateParameters);
            return prms.ToXml(includePrivateParameters);
        }
        #endregion

        public new void Dispose() => Encryptor.Dispose();
    }
}
