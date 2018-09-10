/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.

 This library is provided as-is and is covered by the MIT License [1].

 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Numerics;
using BigIntegerExt;

namespace PaillierExt
{
    public class Paillier : AsymmetricAlgorithm
    {
        private PaillierKeyStruct o_key_struct;
        public PaillierKeyStruct KeyStruct
        {
            get
            {
                if (NeedToGenerateKey())
                {
                    CreateKeyPair(KeySizeValue);
                }
                return o_key_struct;
            }
            set => o_key_struct = value;
        }

        public Paillier()
        {
            o_key_struct = new PaillierKeyStruct
            {
                N = new BigInteger(0),
                G = new BigInteger(0),
                Lambda = new BigInteger(0),
                Miu = new BigInteger(0)
            };

            // set the default key size value
            KeySizeValue = 1024;

            // set the range of legal keys
            LegalKeySizesValue = new[] { new KeySizes(384, 1088, 8) };
        }

        private bool NeedToGenerateKey()
        {
            return o_key_struct.N == 0
                   && o_key_struct.G == 0;
        }

        // TODO: check again for Miu
        private void CreateKeyPair(int p_key_strength)
        {
            // create the large prime number, p and q
            // p and q are assumed to have the same bit length (512 bit each, so that N is 1024)
            using (var x_random_generator = RandomNumberGenerator.Create())
            {
                var p = new BigInteger();
                var q = new BigInteger();

                p = p.GenPseudoPrime(p_key_strength / 2, 16, x_random_generator);
                q = q.GenPseudoPrime(p_key_strength / 2, 16, x_random_generator);

                // compute N
                // n = p*q
                o_key_struct.N = p * q;

                // compute G
                // First option: g is random in Z*(n^2)
                /*var temp = new BigInteger();
                temp = temp.GenRandomBits(2048, x_random_generator);
                o_key_struct.G = temp % o_key_struct.NSquare; // to make sure g is in Z(Nsquare)
                //o_key_struct.G = o_key_struct.G + 1; // to avoid getting G = 0 TODO: research if this <- is necessary*/

                // Second option: g = n + 1
                o_key_struct.G = o_key_struct.N + 1;

                // compute lambda
                // lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
                // or simpler variant, lambda = (p-1)(q-1), since p and q have same length
                //o_key_struct.Lambda = (p - 1) * (q - 1) / BigInteger.GreatestCommonDivisor(p - 1, q - 1);
                o_key_struct.Lambda = (p - 1) * (q - 1);

                // Miu = (L(g^lambda mod NSq))^-1 mod n
                // or simple: Miu = lambda^-1 (mod n)
                //o_key_struct.Miu = ((BigInteger.ModPow(o_key_struct.G, o_key_struct.Lambda, o_key_struct.NSquare) - 1) / o_key_struct.N).ModInverse(o_key_struct.N);
                o_key_struct.Miu = o_key_struct.Lambda.ModInverse(o_key_struct.N);
            }
        }

        public byte[] EncryptData(BigInteger p_data)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            using (var x_enc = new PaillierEncryptor(o_key_struct))
            {
                return x_enc.ProcessBigInteger(p_data);
            }
        }

        public BigInteger DecryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            var x_enc = new PaillierDecryptor(o_key_struct);

            return x_enc.ProcessByteBlock(p_data);
        }

        public byte[] Addition(byte[] p_first, byte[] p_second)
        {
            return Homomorphism.PaillierHomomorphism.Addition(p_first, p_second, o_key_struct.NSquare.ToByteArray());
        }

        public override string ToXmlString(bool p_include_private)
        {
            var x_params = ExportParameters(p_include_private);
            var x_sb = new StringBuilder();

            x_sb.Append("<PaillierKeyValue>");

            x_sb.Append("<N>" + Convert.ToBase64String(x_params.N) + "</N>");
            x_sb.Append("<G>" + Convert.ToBase64String(x_params.G) + "</G>");

            if (p_include_private)
            {
                x_sb.Append("<Lambda>" + Convert.ToBase64String(x_params.Lambda) + "</Lambda>");
                x_sb.Append("<Miu>" + Convert.ToBase64String(x_params.Miu) + "</Miu>");
            }

            x_sb.Append("</PaillierKeyValue>");

            return x_sb.ToString();
        }

        public override void FromXmlString(string p_string)
        {
            var x_params = new PaillierParameters();

            var keyValues = XDocument.Parse(p_string).Element("PaillierKeyValue");

            x_params.N = Convert.FromBase64String((String)keyValues.Element("N") ?? "");
            x_params.G = Convert.FromBase64String((String)keyValues.Element("G") ?? "");
            x_params.Lambda = Convert.FromBase64String((String)keyValues.Element("Lambda") ?? "");
            x_params.Miu = Convert.FromBase64String((String)keyValues.Element("Miu") ?? "");

            ImportParameters(x_params);
        }

        public void ImportParameters(PaillierParameters p_parameters)
        {
            o_key_struct.N = new BigInteger(p_parameters.N);
            o_key_struct.G = new BigInteger(p_parameters.G);

            if (p_parameters.Lambda != null
                && p_parameters.Lambda.Length > 0
                && p_parameters.Miu != null
                && p_parameters.Miu.Length > 0)
            {
                o_key_struct.Lambda = new BigInteger(p_parameters.Lambda);
                o_key_struct.Miu = new BigInteger(p_parameters.Miu);
            }
            else
            {
                o_key_struct.Lambda = BigInteger.Zero;
                o_key_struct.Miu = BigInteger.Zero;
            }

            KeySizeValue = o_key_struct.N.BitCount();
        }

        public PaillierParameters ExportParameters(bool p_include_private_params)
        {
            if (NeedToGenerateKey())
            {
                CreateKeyPair(KeySizeValue);
            }

            var x_params = new PaillierParameters
            {
                N = o_key_struct.N.ToByteArray(),
                G = o_key_struct.G.ToByteArray(),
            };

            // if required, include the private value, X
            if (p_include_private_params)
            {
                x_params.Lambda = o_key_struct.Lambda.ToByteArray();
                x_params.Miu = o_key_struct.Miu.ToByteArray();
            }
            else
            {
                // ensure that we zero the value
                x_params.Lambda = new byte[1];
                x_params.Miu = new byte[1];
            }

            return x_params;
        }
    }
}
