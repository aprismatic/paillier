using Aprismatic.BigFraction;
using System;
using System.Numerics;
using System.Security.Cryptography;
using PaillierExt;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class EdgeCases : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public EdgeCases(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

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

                var z = new BigInteger(0);
                var r = new BigInteger(rnd.Next(1, 65536));

                var z_enc = encryptAlgorithm.EncryptData(z);
                var z_dec = decryptAlgorithm.DecryptData(z_enc);

                Assert.Equal(z, z_dec);

                var r_enc = encryptAlgorithm.EncryptData(r);
                var zar_enc = decryptAlgorithm.Addition(z_enc, r_enc);
                var raz_enc = decryptAlgorithm.Addition(r_enc, z_enc);
                var zar = decryptAlgorithm.DecryptData(zar_enc);
                var raz = decryptAlgorithm.DecryptData(raz_enc);

                Assert.Equal(r, zar);
                Assert.Equal(r, raz);

                algorithm.Dispose();
                encryptAlgorithm.Dispose();
                decryptAlgorithm.Dispose();
            }
        }

        [Fact(DisplayName = "Edge values")]
        public void MinAndMaxValues()
        {
            var max = BigInteger.Pow(2, 255) - 1; // should work
            var max_plus = max + 1; // should throw
            var min = -max; // should work
            var min_minus = min - 1; // should throw

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


                // MAX
                var max_enc = encryptAlgorithm.EncryptData(max);
                var max_dec = decryptAlgorithm.DecryptData(max_enc);
                Assert.True(max_dec == max, $"{Environment.NewLine}{Environment.NewLine}" +
                                            $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                            $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                            $"max     : {max}{Environment.NewLine}{Environment.NewLine}" +
                                            $"max_dec : {max_dec}");

                // MIN
                var min_enc = encryptAlgorithm.EncryptData(min);
                var min_dec = decryptAlgorithm.DecryptData(min_enc);
                Assert.True(min_dec == min, $"{Environment.NewLine}{Environment.NewLine}" +
                                            $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                            $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                            $"min     : {min}{Environment.NewLine}{Environment.NewLine}" +
                                            $"min_dec : {min_dec}");

                // MAX + 1
                Assert.Throws<ArgumentException>(() => encryptAlgorithm.EncryptData(max_plus));

                // MIN - 1
                Assert.Throws<ArgumentException>(() => encryptAlgorithm.EncryptData(min_minus));

                algorithm.Dispose();
                encryptAlgorithm.Dispose();
                decryptAlgorithm.Dispose();
            }
        }
    }
}
