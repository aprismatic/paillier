using BigIntegerExt;
using PaillierExt;
using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PaillierTests
{
    public class PaillierEncryptionTests
    {
       
        [Fact(DisplayName = "Random BigIntegers")]
        public void TestRandomBigIntegers()
        {
            var iterations = 10;
            var rnd = new Random();
            var rng = new RNGCryptoServiceProvider();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                for (var i = 0; i < iterations; i++)
                {
                    Paillier algorithm = new PaillierManaged
                    {
                        KeySize = keySize
                    };

                    Paillier encryptAlgorithm = new PaillierManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    Paillier decryptAlgorithm = new PaillierManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var z = new BigInteger();

                    // Plaintext that is bigger than one block requires different padding (e.g. ANSIX923 or PKCS97)
                    z = z.GenRandomBits(rnd.Next(2, (algorithm as PaillierManaged).KeyStruct.getPlaintextBlocksize() * 8), rng);

                    var z_enc_bytes = encryptAlgorithm.EncryptData(z);
                    var z_dec_bytes = decryptAlgorithm.DecryptData(z_enc_bytes);

                    Assert.Equal(z, z_dec_bytes);
                }
            }
        }


        [Fact(DisplayName = "Specific cases")]
        public void TestSpecificCases()
        {
            {
                Paillier algorithm = new PaillierManaged
                {
                    KeySize = 384
                };

                var z = new BigInteger(138);

                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec_bytes = algorithm.DecryptData(z_enc_bytes);

                Assert.Equal(z, z_dec_bytes);
            }
        }

        [Fact(DisplayName = "Addition batch")]
        public void TestAddition_Batch()
        {
            var iterations = 10;
            var random = new Random();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                for (var i = 0; i < iterations; i++)
                {
                    Paillier algorithm = new PaillierManaged
                    {
                        KeySize = keySize
                    };

                    Paillier encryptAlgorithm = new PaillierManaged();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    Paillier decryptAlgorithm = new PaillierManaged();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var A = new BigInteger(random.Next());
                    var B = new BigInteger(random.Next());

                    //encrypt A and B
                    var A_enc_bytes = encryptAlgorithm.EncryptData(A);
                    var B_enc_bytes = encryptAlgorithm.EncryptData(B);

                    // getting homomorphic addition result
                    var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
                    var C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);


                    Assert.True(A + B == C_dec_bytes, $"Key length: {keySize}{Environment.NewLine}" +
                                                $"A:          {A}{Environment.NewLine}" +
                                                $"B:          {B}{Environment.NewLine}" +
                                                $"A + B:      {A + B}{Environment.NewLine}" +
                                                $"C_dec:      {C_dec_bytes}");
                }
            }
        }

        [Fact(DisplayName = "From issue #15")]
        public void Test_FromIssue_15() // based on https://github.com/bazzilic/PaillierExt/issues/15
        {
            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                Paillier algorithm = new PaillierManaged
                {
                    KeySize = keySize
                };

                var sum = algorithm.EncryptData(new BigInteger(0));
                var one = algorithm.EncryptData(new BigInteger(1));

                for (var i = 0; i < 1000; i++)
                {
                    sum = algorithm.Addition(sum, one);
                }

                var sum_bytes = algorithm.DecryptData(sum);

                Assert.Equal(new BigInteger(1000), sum_bytes);
            }
        }
    }
}
