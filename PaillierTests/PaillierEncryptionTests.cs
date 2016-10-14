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
            // TODO: BigInteger can't hold enough digits for keys larger than 544 bits
            for (var keySize = 384; keySize <= 544; keySize += 8)
            {
                Paillier algorithm = new PaillierManaged();
                algorithm.Padding = PaillierPaddingMode.LeadingZeros;
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
        public void TestRandomBigIntegers()
        {
            var iterations = 10;
            var rnd = new Random();

            // TODO: BigInteger can't hold enough digits for keys larger than 544 bits
            for (var keySize = 384; keySize <= 544; keySize += 8)
            {
                Paillier algorithm = new PaillierManaged();
                algorithm.Padding = PaillierPaddingMode.LeadingZeros;
                algorithm.KeySize = keySize;

                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var z = new BigInteger();

                for (var i = 0; i < iterations; i++)
                {
                    // Plaintext that is bigger than one block requires different padding (e.g. ANSIX923 or PKCS97)
                    z.genRandomBits(rnd.Next(1, (algorithm as PaillierManaged).KeyStruct.getPlaintextBlocksize() * 8), rnd);

                    var z_bytes = z.getBytes();

                    var z_enc_bytes = encryptAlgorithm.EncryptData(z_bytes);
                    var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                    var z_dec = new BigInteger(z_dec_bytes);

                    Assert.AreEqual(z, z_dec);
                }
            }
        }

        //[TestMethod] //TODO: for text need to implement ANSIX923 or PKCS7 padding
        public void TestTextEncryption()
        {
            var message = "This is to test Paillier encryption and hopefully this message contains more than 2 blocks please please please please please please please please please please please pleaseplease please please pleaseplease please please please          ";
            var plaintext = Encoding.Default.GetBytes(message);

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                Paillier algorithm = new PaillierManaged();
                algorithm.Padding = PaillierPaddingMode.Zeros;
                algorithm.KeySize = keySize;

                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                var ciphertext = encryptAlgorithm.EncryptData(plaintext);
                var candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

                CollectionAssert.AreEqual(plaintext, candidatePlaintext);
            }
        }

        [TestMethod]
        public void TestAddition_Batchs()
        {
            var iterations = 10;
            var random = new Random();

            // TODO: BigInteger can't hold enough digits for keys larger than 544 bits
            for (var keySize = 384; keySize <= 544; keySize += 8)
            {
                Paillier algorithm = new PaillierManaged();
                algorithm.Padding = PaillierPaddingMode.LeadingZeros;
                algorithm.KeySize = keySize;

                Paillier encryptAlgorithm = new PaillierManaged();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                Paillier decryptAlgorithm = new PaillierManaged();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                for (var i = 0; i < iterations; i++)
                {
                    var A = new BigInteger(random.Next());
                    var B = new BigInteger(random.Next());

                    var A_bytes = A.getBytes();
                    var B_bytes = B.getBytes();

                    //encrypt A and B
                    var A_enc_bytes = encryptAlgorithm.EncryptData(A_bytes);
                    var B_enc_bytes = encryptAlgorithm.EncryptData(B_bytes);

                    // getting homomorphic addition result
                    var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
                    var C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

                    // convert to BigInteger
                    var C_dec = new BigInteger(C_dec_bytes);

                    Assert.AreEqual(C_dec, A + B);
                }
            }
        }
    }
}
