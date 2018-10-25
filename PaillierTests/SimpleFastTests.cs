using PaillierExt;
using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic.BigFraction;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class SimpleFastTests : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public SimpleFastTests(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
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

                algorithm.Dispose();
            }

            {
                // based on https://github.com/bazzilic/PaillierExt/issues/15
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

                    algorithm.Dispose();
                }
            }
        }

        [Fact(DisplayName = "Simple negatives")]
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

                algorithm.Dispose();
            }
        }

        [Fact(DisplayName = "Simple fractions")]
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

                algorithm.Dispose();
            }
        }

        [Fact(DisplayName = "Simple negative fractions")]
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

                algorithm.Dispose();
            }
        }
    }
}
