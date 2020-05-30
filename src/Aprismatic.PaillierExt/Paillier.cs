using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Numerics;
using Aprismatic.PaillierExt.Homomorphism;

namespace Aprismatic.PaillierExt
{
    public class Paillier : AsymmetricAlgorithm, IDisposable
    {
        private readonly PaillierKeyStruct keyStruct;
        private readonly PaillierEncryptor encryptor;
        private readonly PaillierDecryptor decryptor;

        public Paillier(int keySize)
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
            KeySizeValue = keySize;
            keyStruct = CreateKeyPair();
            encryptor = new PaillierEncryptor(keyStruct);
            decryptor = new PaillierDecryptor(keyStruct);
        }

        public Paillier(PaillierParameters prms)
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            keyStruct = new PaillierKeyStruct(
                new BigInteger(prms.N),
                new BigInteger(prms.G),
                (prms.Lambda?.Length ?? 0) > 0 ? new BigInteger(prms.Lambda) : BigInteger.Zero,
                (prms.Miu?.Length ?? 0) > 0 ? new BigInteger(prms.Miu) : BigInteger.Zero
            );

            KeySizeValue = keyStruct.NLength * 8;

            encryptor = new PaillierEncryptor(keyStruct);
            decryptor = new PaillierDecryptor(keyStruct);
        }

        public Paillier(string Xml)
        {
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };

            var prms = new PaillierParameters();
            var keyValues = XDocument.Parse(Xml).Element("PaillierKeyValue");
            prms.N = Convert.FromBase64String((String) keyValues.Element("N") ?? "");
            prms.G = Convert.FromBase64String((String) keyValues.Element("G") ?? "");
            prms.Lambda = Convert.FromBase64String((String) keyValues.Element("Lambda") ?? "");
            prms.Miu = Convert.FromBase64String((String) keyValues.Element("Miu") ?? "");

            keyStruct = new PaillierKeyStruct(
                new BigInteger(prms.N),
                new BigInteger(prms.G),
                new BigInteger(prms.Lambda),
                new BigInteger(prms.Miu)
            );

            KeySizeValue = keyStruct.NLength * 8;

            encryptor = new PaillierEncryptor(keyStruct);
            decryptor = new PaillierDecryptor(keyStruct);
        }

        public int MaxPlaintextBits() => PaillierKeyStruct.MaxPlaintextBits;
        public BigInteger PlaintextExp => PaillierKeyStruct.PlaintextExp;
        public int GetPlaintextDecPlace() => PaillierKeyStruct.PlaintextDecPlace;

        // TODO: check again for Miu
        private PaillierKeyStruct CreateKeyPair()
        {
            BigInteger N, Lambda, G, Miu;

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

                // compute N
                // N = p*q
                N = p * q;
            } while (N.BitCount() < KeySizeValue - 7);

            // compute G
            //  First option:  G is random in Z*(N^2)
            //  Second option: G = N + 1
            G = N + 1;

            // compute lambda
            //  lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
            //  or simpler variant, lambda = (p-1)(q-1), since p and q have same length
            Lambda = (p - 1) * (q - 1);

            // Miu = (L(g^lambda mod NSq))^-1 mod n
            // or simple: Miu = lambda^-1 (mod n)
            Miu = Lambda.ModInverse(N);

            return new PaillierKeyStruct(N, G, Lambda, Miu);
        }

        public byte[] EncryptDataOld(BigFraction message)
        {
            using (var encryptor = new PaillierEncryptor(keyStruct))
            {
                return encryptor.ProcessBigIntegerOld(message);
            }
        }

        public byte[] EncryptData(BigFraction message)
        {
            var res = new byte[keyStruct.CiphertextBlocksize * 2];
            encryptor.ProcessBigInteger(message, res.AsSpan());
            return res;
        }

        public BigFraction DecryptDataOld(byte[] p_data)
        {
            var decryptor = new PaillierDecryptor(keyStruct);

            return decryptor.ProcessByteBlockOld(p_data);
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

        public override string ToXmlString(bool includePrivateParameters)
        {
            var prms = ExportParameters(includePrivateParameters);
            var sb = new StringBuilder();

            sb.Append("<PaillierKeyValue>");

            sb.Append("<N>" + Convert.ToBase64String(prms.N) + "</N>");
            sb.Append("<G>" + Convert.ToBase64String(prms.G) + "</G>");

            if (includePrivateParameters)
            {
                sb.Append("<Lambda>" + Convert.ToBase64String(prms.Lambda) + "</Lambda>");
                sb.Append("<Miu>" + Convert.ToBase64String(prms.Miu) + "</Miu>");
            }

            sb.Append("</PaillierKeyValue>");

            return sb.ToString();
        }

        public PaillierParameters ExportParameters(bool includePrivateParams)
        {
            var prms = new PaillierParameters
            {
                N = keyStruct.N.ToByteArray(),
                G = keyStruct.G.ToByteArray()
            };

            // if required, include the private value, X
            if (includePrivateParams)
            {
                prms.Lambda = keyStruct.Lambda.ToByteArray();
                prms.Miu = keyStruct.Miu.ToByteArray();
            }
            else
            {
                // ensure that we zero the value
                prms.Lambda = new byte[1];
                prms.Miu = new byte[1];
            }

            return prms;
        }

        public new void Dispose()
        {
            encryptor.Dispose();
        }
    }
}
