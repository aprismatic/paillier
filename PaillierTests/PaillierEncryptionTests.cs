using PaillierExt;
using System;
using System.Numerics;
using Xunit;
using Numerics;

namespace PaillierTests
{
    public class PaillierEncryptionTests
    {

        [Fact(DisplayName = "Zero")]
        public void TestZero()
        {
            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                var algorithm = new Paillier
                {
                    KeySize = keySize
                };
                var encryptAlgorithm = new Paillier();
                encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));
                var decryptAlgorithm = new Paillier();
                decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));
                BigFraction z = new BigInteger(0);
                var z_enc_bytes = encryptAlgorithm.EncryptData(z);
                BigFraction z_dec = decryptAlgorithm.DecryptData(z_enc_bytes);

                Assert.Equal(z, z_dec);
            }
        }

        [Fact(DisplayName = "Large BigIntegers")]
        public void TestLargeBigIntegers()
        {
            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                var algorithm = new Paillier
                {
                    KeySize = keySize
                };

                //9 hundred trillion
                var t = new BigInteger(900000000000000);

                BigFraction z = t;

                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);

                Assert.Equal(z, z_dec);
            }
        }


        [Fact(DisplayName = "Specific cases")]
        public void TestSpecificCases()
        {
            {
                var algorithm = new Paillier
                {
                    KeySize = 384
                };

                var z = new BigFraction(BigInteger.Parse("1000"), BigInteger.Parse("1"));

                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);

                Assert.Equal(z, z_dec);
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
                    var algorithm = new Paillier
                    {
                        KeySize = keySize
                    };

                    var encryptAlgorithm = new Paillier();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    var decryptAlgorithm = new Paillier();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var A = new BigInteger(random.Next());
                    var B = new BigInteger(random.Next());

                    //encrypt A and B
                    var A_enc_bytes = encryptAlgorithm.EncryptData(A);
                    var B_enc_bytes = encryptAlgorithm.EncryptData(B);

                    // getting homomorphic addition result
                    var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
                    var C_dec = decryptAlgorithm.DecryptData(C_enc_bytes);


                    Assert.True(A + B == C_dec, $"Key length: {keySize}{Environment.NewLine}" +
                                                $"A:          {A}{Environment.NewLine}" +
                                                $"B:          {B}{Environment.NewLine}" +
                                                $"A + B:      {A + B}{Environment.NewLine}" +
                                                $"C_dec:      {C_dec}");
                }
            }
        }

        [Fact(DisplayName = "From issue #15")]
        public void Test_FromIssue_15() // based on https://github.com/bazzilic/PaillierExt/issues/15
        {
            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                var algorithm = new Paillier
                {
                    KeySize = keySize
                };

                var sum = algorithm.EncryptData(new BigInteger(0));
                var one = algorithm.EncryptData(new BigInteger(1));

                for (var i = 0; i < 1000; i++)
                {
                    sum = algorithm.Addition(sum, one);
                }

                var sums = algorithm.DecryptData(sum);

                Assert.Equal(sums, new BigInteger(1000));
            }
        }

        [Fact(DisplayName = "Negative cases")]
        public void TestNegativeCases()
        {
            {
                var algorithm = new Paillier
                {
                    KeySize = 384
                };

                //Test negative number
                var z = new BigInteger(-600000000000000000);
                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);
                Assert.Equal(z, z_dec);

                //Test positive number
                var z_2 = new BigInteger(6);
                var z_enc_bytes_2 = algorithm.EncryptData(z_2);
                var z_dec_2 = algorithm.DecryptData(z_enc_bytes_2);
                Assert.Equal(z_2, z_dec_2);

                //Test addition of positive and negative numbers
                var z_enc_addition = algorithm.Addition(z_enc_bytes, z_enc_bytes_2);
                var z_addition = algorithm.DecryptData(z_enc_addition);
                Assert.Equal(z + z_2, z_addition);
            }
        }

        [Fact(DisplayName = "Floating point")]
        public void TestFloatingPoint()
        {
            {
                var algorithm = new Paillier
                {
                    KeySize = 384
                };

                //Test 1 decimal place
                var z = new BigFraction(BigInteger.Parse("1"), BigInteger.Parse("10"));
                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);
                Assert.Equal(z, z_dec);

                //Test 0 < plaintext < 1
                var z_3 = new BigFraction(BigInteger.Parse("1"), BigInteger.Parse("100"));
                var z_3_enc_bytes = algorithm.EncryptData(z_3);
                var z_3_dec = algorithm.DecryptData(z_3_enc_bytes);
                Assert.Equal(z_3, z_3_dec);

                //Test plaintext > 1
                var z_2 = new BigFraction(BigInteger.Parse("10000000001"), BigInteger.Parse("100"));
                var z_2_enc_bytes = algorithm.EncryptData(z_2);
                var z_2_dec = algorithm.DecryptData(z_2_enc_bytes);
                Assert.Equal(z_2, z_2_dec);

                //Test addition
                var z_enc_addition = algorithm.Addition(z_enc_bytes, z_2_enc_bytes);
                var z_addition = algorithm.DecryptData(z_enc_addition);
                Assert.Equal(z + z_2, z_addition);
            }
        }

        [Fact(DisplayName = "Negative Floating point")]
        public void TestNegativeFloatingPoint()
        {
            {
                var algorithm = new Paillier
                {
                    KeySize = 384
                };

                //Test 0 > plaintext > -1
                var z = new BigFraction(BigInteger.Parse("-1001"), BigInteger.Parse("100"));
                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);
                Assert.Equal(z, z_dec);

                //Test plaintext < -1
                var z_2 = new BigFraction(BigInteger.Parse("-1000000001"), BigInteger.Parse("100"));
                var z_2_enc_bytes = algorithm.EncryptData(z_2);
                var z_2_dec = algorithm.DecryptData(z_2_enc_bytes);
                Assert.Equal(z_2, z_2_dec);

                //Test addition
                var z_enc_addition = algorithm.Addition(z_enc_bytes, z_2_enc_bytes);
                var z_addition = algorithm.DecryptData(z_enc_addition);
                Assert.Equal(z + z_2, z_addition);
            }
        }
    }
}
