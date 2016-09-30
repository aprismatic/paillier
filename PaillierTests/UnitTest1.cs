using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PaillierExt;
using System.Text;
using System.Linq;
using System.Security.Cryptography;

namespace PaillierTests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestZero()
        {
            Paillier algorithm = new PaillierManaged();
            algorithm.Padding = PaillierPaddingMode.LeadingZeros;

            for (algorithm.KeySize = 384; algorithm.KeySize <= 544; algorithm.KeySize += 8)
            {
                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger(0);

                var z_enc = encryptAlgorithm.EncryptData(z.getBytes());
                var z_dec = decryptAlgorithm.DecryptData(z_enc);

                for(int i = 0; i < z_dec.Length; i++)
                {
                    Assert.AreEqual(z_dec[i], 0);
                }
            }
        }

        [TestMethod]
        public void TestRandomBI()
        {
            // Failed test because of zeroes

            Paillier algorithm = new PaillierManaged();
            algorithm.Padding = PaillierPaddingMode.LeadingZeros;

            for (algorithm.KeySize = 384; algorithm.KeySize <= 544; algorithm.KeySize += 8)
            {
                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger();
                z.genRandomBits(new Random().Next(1, 2241), new RNGCryptoServiceProvider());

                var z_enc = encryptAlgorithm.EncryptData(z.getBytes());
                var z_dec = decryptAlgorithm.DecryptData(z_enc);

                Assert.IsTrue(z.getBytes().SequenceEqual(z_dec));
            }
        }

        [TestMethod]
        public void TestTextEncryption()
        {
            // Test failed somehow. 
            // UPDATE: This test unexpectedly passed. I guess it's due to the BigInteger package update.
            string message = "This is to test Paillier encryption and hopefully this message contains more than 2 blocks please please please please please please please please please please please pleaseplease please please pleaseplease please please please          ";
            PaillierPaddingMode padding = PaillierPaddingMode.Zeros;

            var plaintext = Encoding.Default.GetBytes(message);

            Paillier algorithm = new PaillierManaged();

            for (int keySize = 384; keySize <= 544; keySize += 8)
            {
                algorithm.KeySize = keySize;
                algorithm.Padding = padding;

                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                var ciphertext = encryptAlgorithm.EncryptData(plaintext);

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

                var strip_zeros = StripTrailingZeros(candidatePlaintext, plaintext.Length);

                Assert.IsTrue(plaintext.SequenceEqual(strip_zeros));
            }
        }

        [TestMethod]
        public void TestAddition_Batchs()
        {
            var iteration = 40;

            for (var i = 0; i < iteration; i++)
            {
                for (int keySize = 384; keySize <= 544; keySize += 8)
                {
                    Assert.IsTrue(TestAddition(keySize));
                }
            }
        }

        public static bool TestAddition(int keySize)
        {
            Paillier algorithm = new PaillierManaged();
            algorithm.KeySize = keySize;
            algorithm.Padding = PaillierPaddingMode.LeadingZeros;

            string parametersXML = algorithm.ToXmlString(true);

            Paillier encryptAlgorithm = new PaillierManaged();
            encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

            Paillier decryptAlgorithm = new PaillierManaged();
            decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

            var random = new Random();
            var A = new BigInteger(random.Next(32768));
            var B = new BigInteger(random.Next(32768));

            var A_bytes = A.getBytes();
            var B_bytes = B.getBytes();

            //encrypt A and B
            var A_enc_bytes = encryptAlgorithm.EncryptData(A_bytes);
            var B_enc_bytes = encryptAlgorithm.EncryptData(B_bytes);

            // decrypt A and B
            var A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
            var B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

            // getting homomorphic addition result
            var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
            var C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

            // convert to BigInteger
            var A_dec = new BigInteger(A_dec_bytes);
            var B_dec = new BigInteger(B_dec_bytes);
            var C_dec = new BigInteger(C_dec_bytes);

            if (C_dec != A + B)
            {
                return false;
            }

            return true;
        }

        public static byte[] StripTrailingZeros(byte[] array, int arrayLength)
        {
            var array_stripped = new byte[arrayLength];

            Array.Copy(array, 0, array_stripped, 0, arrayLength);

            return array_stripped;
        }
    }
}
