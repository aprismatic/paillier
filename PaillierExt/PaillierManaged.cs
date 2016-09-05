﻿/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.
 
 This library is provided as-is and is covered by the MIT License [1].
  
 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;
using System.Security.Cryptography;

namespace PaillierExt
{
    public class PaillierManaged : Paillier
    {
        private PaillierKeyStruct o_key_struct;

        public PaillierManaged()
        {
            // create the key struct
            o_key_struct = new PaillierKeyStruct();

            // set all of the big integers to zero
            o_key_struct.N = new BigInteger(0);
            o_key_struct.G = new BigInteger(0);
            o_key_struct.Lambda = new BigInteger(0);
            o_key_struct.Miu = new BigInteger(0);

            // set the default key size value
            KeySizeValue = 1024;

            // set the default padding mode
            Padding = PaillierPaddingMode.LeadingZeros;

            // set the range of legal keys
            LegalKeySizesValue = new KeySizes[] { new KeySizes(384, 1088, 8) };
        }

        public override string SignatureAlgorithm
        {
            get
            {
                return "Paillier";
            }
        }

        public override string KeyExchangeAlgorithm
        {
            get
            {
                return "Paillier";
            }
        }

        // TODO: check again for Miu
        // p_key_strength in normal case is passed in by keysizevalue, which is 1024
        private void CreateKeyPair(int p_key_strength)
        {
            // create the large prime number, p and q
            // p and q are assumed to have the same bit length (512 bit each, so that N is 1024)
            // public static BigInteger genPseudoPrime(int bits, int confidence, RNGCryptoServiceProvider rand)
            using (RNGCryptoServiceProvider x_random_generator = new RNGCryptoServiceProvider())
            {
                var p = BigInteger.genPseudoPrime(p_key_strength / 2, 16, x_random_generator);
                var q = BigInteger.genPseudoPrime(p_key_strength / 2, 16, x_random_generator);

                // compute N
                // n = p*q
                o_key_struct.N = p * q;

                // compute G
                // g is random in Z*(n^2)
                // g = n+1 (simpler variant)
                //o_key_struct.G = o_key_struct.N + 1;
                var temp = new BigInteger();

                temp.genRandomBits(2048, x_random_generator);

                o_key_struct.G = temp % (o_key_struct.N * o_key_struct.N);  //to make sure g is in Z(Nsquare)
                                                                            //TODO: research if this is necessary, see below
                                                                            //o_key_struct.G = o_key_struct.G + 1; // to avoid getting G = 0

                // compute lambda
                // lambda = lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1)
                // or simpler variant, lambda = (p-1)(q-1), since p and q have same length
                //o_key_struct.Lambda = (p - 1) * (q - 1);
                o_key_struct.Lambda = (p - 1) * (q - 1) / (p - 1).gcd(q - 1);

                // Miu =  lambda**-1 (mod n)
                //o_key_struct.Miu = o_key_struct.Lambda.modInverse(o_key_struct.N);
                o_key_struct.Miu = ((o_key_struct.G.modPow(o_key_struct.Lambda, o_key_struct.N * o_key_struct.N) - 1)
                            / o_key_struct.N).modInverse(o_key_struct.N);

                o_key_struct.Padding = this.Padding;
            }
        }

        // check if public key has been generated by user
        private bool NeedToGenerateKey()
        {
            return o_key_struct.N == 0 && o_key_struct.G == 0;
        }

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
            set
            {
                o_key_struct = value;
            }
        }

        public override void ImportParameters(PaillierParameters p_parameters)
        {
            // obtain the  big integer values from the byte parameter values
            o_key_struct.N = new BigInteger(p_parameters.N);
            o_key_struct.G = new BigInteger(p_parameters.G);
            o_key_struct.Padding = p_parameters.Padding;

            if ((p_parameters.Lambda != null)
             && (p_parameters.Lambda.Length > 0)
             && (p_parameters.Miu != null)
             && (p_parameters.Miu.Length > 0))
            {
                o_key_struct.Lambda = new BigInteger(p_parameters.Lambda);
                o_key_struct.Miu = new BigInteger(p_parameters.Miu);
            }

            // set the length of the key based on the import
            KeySizeValue = o_key_struct.N.bitCount();
        }

        public override PaillierParameters ExportParameters(bool p_include_private_params)
        {
            if (NeedToGenerateKey())
            {
                // we need to create a new key before we can export 
                CreateKeyPair(KeySizeValue);
            }

            // create the parameter set
            PaillierParameters x_params = new PaillierParameters();

            // set the public values of the parameters
            x_params.N = o_key_struct.N.getBytes();
            x_params.G = o_key_struct.G.getBytes();
            x_params.Padding = o_key_struct.Padding;

            // if required, include the private value, X
            if (p_include_private_params)
            {
                x_params.Lambda = o_key_struct.Lambda.getBytes();
                x_params.Miu = o_key_struct.Miu.getBytes();
            }
            else
            {
                // ensure that we zero the value
                x_params.Lambda = new byte[1];
                x_params.Miu = new byte[1];
            }

            return x_params;
        }

        public override byte[] EncryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                // we need to create a new key before we can export 
                CreateKeyPair(KeySizeValue);
            }

            // encrypt the data
            PaillierEncryptor x_enc = new PaillierEncryptor(o_key_struct);

            return x_enc.ProcessData(p_data);
        }

        public override byte[] DecryptData(byte[] p_data)
        {
            if (NeedToGenerateKey())
            {
                // we need to create a new key before we can export 
                CreateKeyPair(KeySizeValue);
            }

            // encrypt the data
            PaillierDecryptor x_enc = new PaillierDecryptor(o_key_struct);

            return x_enc.ProcessData(p_data);
        }

        protected override void Dispose(bool p_bool)
        {
            // do nothing - no unmanaged resources to release
        }

        public override byte[] Sign(byte[] p_hashcode)
        {
            throw new NotImplementedException();
        }

        public override bool VerifySignature(byte[] p_hashcode, byte[] p_signature)
        {
            throw new NotImplementedException();
        }

        // ********** SPECIAL ************//
        // p_first and p_second are already encrypted
        // return homomorphic sum of the 2 plaintext
        public override byte[] Addition(byte[] p_first, byte[] p_second)
        {
            var blocksize = o_key_struct.getCiphertextBlocksize();

            if (p_first.Length != blocksize)
            {
                throw new ArgumentException("p_first", "Ciphertext to multiply should be exactly one block long.");
            }
            if (p_second.Length != blocksize)
            {
                throw new ArgumentException("p_second", "Ciphertext to multiply should be exactly one block long.");
            }

            return Homomorphism.PaillierHomomorphism.Addition(p_first, p_second, o_key_struct.N.getBytes());
        }


    }
}
