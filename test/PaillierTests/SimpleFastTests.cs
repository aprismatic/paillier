﻿using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.Paillier;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class SimpleFastTests : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public SimpleFastTests(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new Paillier(512);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / tmpElG.LegalKeySizes[0].SkipSize;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "Specific cases")]
        public void TestSpecificCases()
        {
            {
                var algorithm = new Paillier(minKeySize);

                var z = new BigFraction(BigInteger.Parse("1000"), BigInteger.Parse("1"));

                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);

                Assert.Equal(z, z_dec);

                algorithm.Dispose();
            }

            {
                // based on https://github.com/bazzilic/PaillierExt/issues/15
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    var algorithm = new Paillier(keySize);

                    var sum = algorithm.EncryptData(new BigInteger(0));
                    var one = algorithm.EncryptData(new BigInteger(1));

                    for (var i = 0; i < 1000; i++)
                    {
                        sum = algorithm.Add(sum, one);
                    }

                    var sums = algorithm.DecryptData(sum);

                    Assert.Equal(sums, new BigInteger(1000));

                    algorithm.Dispose();
                }
            }

            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    var algorithm = new Paillier(keySize);

                    var a = 123;
                    var b = 234;
                    var c = -765;
                    var d = -345;

                    var ae = algorithm.EncryptData(a);
                    var be = algorithm.EncryptData(b);
                    var ce = algorithm.EncryptData(c);
                    var de = algorithm.EncryptData(d);

                    var res = algorithm.Add(ae, be);
                    Assert.Equal(a + b, algorithm.DecryptData(res));

                    res = algorithm.Add(res, ce);
                    Assert.Equal(a + b + c, algorithm.DecryptData(res));

                    res = algorithm.Add(res, de);
                    Assert.Equal(a + b + c + d, algorithm.DecryptData(res));

                    res = algorithm.Subtract(res, be);
                    Assert.Equal(a + c + d, algorithm.DecryptData(res));

                    res = algorithm.Subtract(res, de);
                    Assert.Equal(a + c, algorithm.DecryptData(res));

                    res = algorithm.Subtract(res, ae);
                    Assert.Equal(c, algorithm.DecryptData(res));

                    res = algorithm.Subtract(res, ce);
                    Assert.Equal(0, algorithm.DecryptData(res));

                    algorithm.Dispose();
                }
            }
        }

        [Fact(DisplayName = "Simple negatives")]
        public void TestNegativeCases()
        {
            {
                var algorithm = new Paillier(minKeySize);

                //Test negative number
                var z = new BigInteger(8);
                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);
                Assert.Equal(z, z_dec);

                //Test positive number
                var z_2 = new BigInteger(10);
                var z_enc_bytes_2 = algorithm.EncryptData(z_2);
                var z_dec_2 = algorithm.DecryptData(z_enc_bytes_2);
                Assert.Equal(z_2, z_dec_2);

                //Test addition of positive and negative numbers
                var z_enc_addition = algorithm.Add(z_enc_bytes, z_enc_bytes_2);
                var z_addition = algorithm.DecryptData(z_enc_addition);
                Assert.Equal(z + z_2, z_addition);

                //Test subtraction of positive and negative numbers
                var z_enc_subtraction = algorithm.Subtract(z_enc_bytes, z_enc_bytes_2);
                var z_subtraction = algorithm.DecryptData(z_enc_subtraction);
                Assert.Equal(z - z_2, z_subtraction);

                algorithm.Dispose();
            }
        }

        [Fact(DisplayName = "Simple floating point")]
        public void TestFloatingPoint()
        {
            {
                var algorithm = new Paillier(minKeySize);

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
                var z_enc_addition = algorithm.Add(z_enc_bytes, z_2_enc_bytes);
                var z_addition = algorithm.DecryptData(z_enc_addition);
                Assert.Equal(z + z_2, z_addition);

                algorithm.Dispose();
            }
        }

        [Fact(DisplayName = "Simple negative floating point")]
        public void TestNegativeFloatingPoint()
        {
            {
                var algorithm = new Paillier(minKeySize);

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
                var z_enc_addition = algorithm.Add(z_enc_bytes, z_2_enc_bytes);
                var z_addition = algorithm.DecryptData(z_enc_addition);
                Assert.Equal(z + z_2, z_addition);

                algorithm.Dispose();
            }
        }
    }
}
