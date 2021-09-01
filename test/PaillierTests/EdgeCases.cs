using System;
using System.Numerics;
using Aprismatic;
using System.Security.Cryptography;
using Aprismatic.PaillierExt;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class EdgeCases : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public EdgeCases(ITestOutputHelper output)
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

        [Fact(DisplayName = "Zero")]
        public void TestZero()
        {
            for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
            {
                var algorithm = new Paillier(keySize);

                var encryptAlgorithm = new Paillier(algorithm.ToXmlString(false));
                var decryptAlgorithm = new Paillier(algorithm.ToXmlString(true));

                var z = new BigInteger(0);
                var r = new BigInteger(rnd.Next(1, 65536));

                var z_enc = encryptAlgorithm.EncryptData(z);
                var z_dec = decryptAlgorithm.DecryptData(z_enc);

                Assert.Equal(z, z_dec);

                var r_enc = encryptAlgorithm.EncryptData(r);
                var zar_enc = decryptAlgorithm.Add(z_enc, r_enc);
                var raz_enc = decryptAlgorithm.Add(r_enc, z_enc);
                var zsr_enc = decryptAlgorithm.Subtract(z_enc, r_enc);
                var rsz_enc = decryptAlgorithm.Subtract(r_enc, z_enc);
                var zar = decryptAlgorithm.DecryptData(zar_enc);
                var raz = decryptAlgorithm.DecryptData(raz_enc);
                var zsr = decryptAlgorithm.DecryptData(zsr_enc);
                var rsz = decryptAlgorithm.DecryptData(rsz_enc);

                Assert.Equal(r, zar);
                Assert.Equal(r, raz);
                Assert.Equal(0-r, zsr);
                Assert.Equal(r, rsz);

                algorithm.Dispose();
                encryptAlgorithm.Dispose();
                decryptAlgorithm.Dispose();
            }
        }

        [Fact(DisplayName = "Edge values")]
        public void MinAndMaxValues()
        {
            var max = BigInteger.Pow(2, 127) - 1; // should work
            var max_plus = max + 1; // should throw
            var min = -max; // should work
            var min_minus = min - 1; // should throw

            for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
            {
                var algorithm = new Paillier(keySize);

                var encryptAlgorithm = new Paillier(algorithm.ToXmlString(false));
                var decryptAlgorithm = new Paillier(algorithm.ToXmlString(true));

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

        [Fact(DisplayName = "Big Denominator")]
        public void BigDenominator()
        {
            for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
            {
                var algorithm = new Paillier(keySize);

                var encryptAlgorithm = new Paillier(algorithm.ToXmlString(false));
                var decryptAlgorithm = new Paillier(algorithm.ToXmlString(true));

                var n = new BigInteger(10000);
                var d = algorithm.PlaintextExp * 2;
                var f = new BigFraction(n, d);

                var f_enc = encryptAlgorithm.EncryptData(f);
                var f_dec = decryptAlgorithm.DecryptData(f_enc);

                Assert.Equal(f, f_dec);

                algorithm.Dispose();
                encryptAlgorithm.Dispose();
                decryptAlgorithm.Dispose();
            }
        }
    }
}
