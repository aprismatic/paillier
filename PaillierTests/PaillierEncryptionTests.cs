using Microsoft.VisualStudio.TestTools.UnitTesting;
using PaillierExt;
using System;
using System.Security.Cryptography;
using System.Text;

namespace PaillierTests
{
    [TestClass]
    public class PaillierEncryptionTests
    {
        [TestMethod]
        public void TestZero()
        {
            Paillier algorithm = new PaillierManaged();
            algorithm.Padding = PaillierPaddingMode.LeadingZeros;

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                algorithm.KeySize = keySize;

                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger(0);
                var z_bytes = z.getBytes();

                var z_enc_bytes = encryptAlgorithm.EncryptData(z_bytes);
                var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                var z_dec = new BigInteger(z_dec_bytes);

                Assert.AreEqual(z, z_dec);
            }
        }

        [TestMethod]
        public void TestRandomBI()
        {
            // Failed test because of zeroes
            Paillier algorithm = new PaillierManaged();
            algorithm.Padding = PaillierPaddingMode.LeadingZeros;

            for (algorithm.KeySize = 384; algorithm.KeySize <= 1088; algorithm.KeySize += 8)
            {
                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger();
                z.genRandomBits(new Random().Next(1, 2241), new RNGCryptoServiceProvider());

                var z_bytes = z.getBytes();

                var z_enc_bytes = encryptAlgorithm.EncryptData(z_bytes);
                var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                var z_dec = new BigInteger(z_dec_bytes);

                Assert.AreEqual(z, z_dec);
            }
        }

        //[TestMethod] //TODO: fix trailing zeros issue and enable the test back up
        public void TestTextEncryption()
        {
            var message = "This is to test Paillier encryption and hopefully this message contains more than 2 blocks please please please please please please please please please please please pleaseplease please please pleaseplease please please please          ";
            PaillierPaddingMode padding = PaillierPaddingMode.Zeros;

            var plaintext = Encoding.Default.GetBytes(message);

            Paillier algorithm = new PaillierManaged();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                algorithm.KeySize = keySize;
                algorithm.Padding = padding;

                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                var ciphertext = encryptAlgorithm.EncryptData(plaintext);

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

                CollectionAssert.AreEqual(plaintext, candidatePlaintext);
            }
        }

        [TestMethod]
        public void TestAddition_Batchs()
        {
            var iteration = 5;

            for (var i = 0; i < iteration; i++)
            {
                for (int keySize = 384; keySize <= 544; keySize += 8)
                {
                    Assert.IsTrue(TestAddition(keySize));
                }
            }
        }

        private bool TestAddition(int keySize)
        {
            Paillier algorithm = new PaillierManaged();
            algorithm.KeySize = keySize;
            algorithm.Padding = PaillierPaddingMode.LeadingZeros;

            var parametersXML = algorithm.ToXmlString(true);

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
    }
}
