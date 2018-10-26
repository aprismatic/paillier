using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Numerics;
using Aprismatic.PaillierExt.Homomorphism;

namespace Aprismatic.PaillierExt
{
    public class Paillier : AsymmetricAlgorithm
    {
        private PaillierKeyStruct keyStruct;

        public PaillierKeyStruct KeyStruct
        {
            get
            {
                if (NeedToGenerateKey())
                {
                    CreateKeyPair(KeySizeValue);
                }
                return keyStruct;
            }
            set => keyStruct = value;
        }

        public Paillier()
        {
            keyStruct = new PaillierKeyStruct
            {
                N = BigInteger.Zero,
                G = BigInteger.Zero,
                Lambda = BigInteger.Zero,
                Miu = BigInteger.Zero
            };

            // set the default key size value
            KeySizeValue = 1024;

            // set the range of legal keys
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
        }

        private bool NeedToGenerateKey()
        {
            return keyStruct.N == 0
                   && keyStruct.G == 0;
        }

        // TODO: check again for Miu
        private void CreateKeyPair(int pKeyStrength)
        {
            // create the large prime number, p and q
            // p and q are assumed to have the same bit length (512 bit each, so that N is 1024)
            using (var rng = RandomNumberGenerator.Create())
            {
                var p = new BigInteger();
                var q = new BigInteger();

                p = p.GenPseudoPrime(pKeyStrength / 2, 16, rng);
                q = q.GenPseudoPrime(pKeyStrength / 2, 16, rng);

                // compute N
                // n = p*q
                keyStruct.N = p * q;

                // compute G
                // First option: g is random in Z*(n^2)

                // Second option: g = n + 1
                keyStruct.G = keyStruct.N + 1;

                // compute lambda
                // lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
                // or simpler variant, lambda = (p-1)(q-1), since p and q have same length
                keyStruct.Lambda = (p - 1) * (q - 1);

                // Miu = (L(g^lambda mod NSq))^-1 mod n
                // or simple: Miu = lambda^-1 (mod n)
                keyStruct.Miu = keyStruct.Lambda.ModInverse(keyStruct.N);
            }
        }

        public byte[] EncryptData(BigFraction message)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            using (var encryptor = new PaillierEncryptor(keyStruct))
            {
                return encryptor.ProcessBigInteger(message);
            }
        }

        public BigFraction DecryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            var decryptor = new PaillierDecryptor(keyStruct);

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

        public override void FromXmlString(string str)
        {
            var prms = new PaillierParameters();

            var keyValues = XDocument.Parse(str).Element("PaillierKeyValue");

            prms.N = Convert.FromBase64String((String)keyValues.Element("N") ?? "");
            prms.G = Convert.FromBase64String((String)keyValues.Element("G") ?? "");
            prms.Lambda = Convert.FromBase64String((String)keyValues.Element("Lambda") ?? "");
            prms.Miu = Convert.FromBase64String((String)keyValues.Element("Miu") ?? "");

            ImportParameters(prms);
        }

        public void ImportParameters(PaillierParameters parameters)
        {
            keyStruct.N = new BigInteger(parameters.N);
            keyStruct.G = new BigInteger(parameters.G);

            if (parameters.Lambda != null
                && parameters.Lambda.Length > 0
                && parameters.Miu != null
                && parameters.Miu.Length > 0)
            {
                keyStruct.Lambda = new BigInteger(parameters.Lambda);
                keyStruct.Miu = new BigInteger(parameters.Miu);
            }
            else
            {
                keyStruct.Lambda = BigInteger.Zero;
                keyStruct.Miu = BigInteger.Zero;
            }

            KeySizeValue = keyStruct.N.BitCount();
        }

        public PaillierParameters ExportParameters(bool includePrivateParams)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            var prms = new PaillierParameters
            {
                N = keyStruct.N.ToByteArray(),
                G = keyStruct.G.ToByteArray(),
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
    }
}
