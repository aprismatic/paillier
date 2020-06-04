using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.PaillierExt;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class IntAddSub : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        public IntAddSub(ITestOutputHelper output)
        {
            this.output = output;
        }

        public void Dispose()
        {
            rng.Dispose();
        }

        [Fact(DisplayName = "INT (ADD/SUB, +-)")]
        public void TestMultiplication_Batch()
        {
            var rnd = new Random();
            var rng = new RNGCryptoServiceProvider();

            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = 384; keySize <= 1088; keySize += 8)
                {
                    var algorithm = new Paillier(keySize);

                    var encryptAlgorithm = new Paillier(algorithm.ToXmlString(false));
                    var decryptAlgorithm = new Paillier(algorithm.ToXmlString(true));

                    BigInteger a, b;
                    do
                    {
                        a = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                    } while (a == 0);
                    do
                    {
                        b = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                    } while (b == 0);

                    if (rnd.Next() % 2 == 0) // randomly change signs
                        a = -a;
                    if (rnd.Next() % 2 == 0)
                        b = -b;

                    var a_enc = encryptAlgorithm.EncryptData(a);
                    var b_enc = encryptAlgorithm.EncryptData(b);


                    // Addition
                    var aab_enc = decryptAlgorithm.Add(a_enc, b_enc);
                    var aab_dec = decryptAlgorithm.DecryptData(aab_enc);
                    Assert.True(aab_dec == a + b, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a + b   : {a + b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"aab_dec : {aab_dec}");

                    var baa_enc = decryptAlgorithm.Add(b_enc, a_enc); // verify transitivity
                    var baa_dec = decryptAlgorithm.DecryptData(baa_enc);
                    Assert.True(baa_dec == b + a, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b + a   : {b + a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"baa_dec : {baa_dec}");

                    // Subtraction
                    var asb_enc = decryptAlgorithm.Subtract(a_enc, b_enc);
                    var asb_dec = decryptAlgorithm.DecryptData(asb_enc);
                    Assert.True(asb_dec == a - b, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a - b   : {a - b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"asb_dec : {asb_dec}");

                    var bsa_enc = decryptAlgorithm.Subtract(b_enc, a_enc);
                    var bsa_dec = decryptAlgorithm.DecryptData(bsa_enc);
                    Assert.True(bsa_dec == b - a, $"{Environment.NewLine}{Environment.NewLine}" +
                                                  $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                                  $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b       : {b}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"b - a   : {b - a}{Environment.NewLine}{Environment.NewLine}" +
                                                  $"bsa_dec : {bsa_dec}");

                    algorithm.Dispose();
                    encryptAlgorithm.Dispose();
                    decryptAlgorithm.Dispose();
                }
            }
        }

    }
}
