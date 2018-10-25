using Aprismatic.BigIntegerExt;
using System;
using System.Numerics;
using System.Security.Cryptography;
using PaillierExt;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class IntAdd : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public IntAdd(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "INT (ADD, +-)")]
        public void TestMultiplication_Batch()
        {
            var rnd = new Random();
            var rng = new RNGCryptoServiceProvider();

            for (var i = 0; i < Globals.iterations; i++)
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

                    BigInteger a, b;
                    do
                    {
                        a = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.KeyStruct.getMaxPlaintextBits() / 4), rng);
                    } while (a == 0);
                    do
                    {
                        b = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.KeyStruct.getMaxPlaintextBits() / 4), rng);
                    } while (b == 0);

                    if (rnd.Next() % 2 == 0) // randomly change signs
                        a = -a;
                    if (rnd.Next() % 2 == 0)
                        b = -b;

                    var a_enc = encryptAlgorithm.EncryptData(a);
                    var b_enc = encryptAlgorithm.EncryptData(b);


                    // Addition
                    var aab_enc = decryptAlgorithm.Addition(a_enc, b_enc);
                    var aab_dec = decryptAlgorithm.DecryptData(aab_enc);
                    Assert.True(aab_dec == a + b, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a + b   : {a * b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"aab_dec : {aab_dec}");

                    var baa_enc = decryptAlgorithm.Addition(b_enc, a_enc); // verify transitivity
                    var baa_dec = decryptAlgorithm.DecryptData(baa_enc);
                    Assert.True(baa_dec == a + b, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b + a   : {b * a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"baa_dec : {baa_dec}");

                    algorithm.Dispose();
                    encryptAlgorithm.Dispose();
                    decryptAlgorithm.Dispose();
                }
            }
        }

    }
}
