using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.Paillier;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class PlaintextOperations : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new();
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public PlaintextOperations(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new Paillier(512);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / tmpElG.LegalKeySizes[0].SkipSize;
        }

        public void Dispose() => rng.Dispose();

        [Fact(DisplayName = "PLAINTEXT (Add)")]
        public void TestPlaintextAdd()
        {
            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    var algorithm = new Paillier(keySize);

                    var encryptAlgorithm = new Paillier(algorithm.ToXmlString(false));
                    var decryptAlgorithm = new Paillier(algorithm.ToXmlString(true));

                    var an = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                    var ad = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                    var a = new BigFraction(an, ad);
                    if (rnd.Next() % 2 == 0) // randomly change signs
                        a = -a;

                    var a_enc = encryptAlgorithm.EncryptData(a);

                    var kn = new BigInteger().GenRandomBits(0, algorithm.MaxEncryptableValue / 4, rng);
                    var kd = new BigInteger().GenRandomBits(0, algorithm.MaxEncryptableValue / 4, rng);
                    var k = new BigFraction(kn, kd);

                    var res = algorithm.PlaintextAdd(a_enc, k);

                    var res_dec = decryptAlgorithm.DecryptData(res);

                    var epsilon = new BigFraction(2, algorithm.PlaintextExp);
                    Assert.True(BigFraction.Abs(res_dec - (a + k)) <= epsilon,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"k       : {k}{Environment.NewLine}{Environment.NewLine}" +
                        $"a + k   : {(a + k).Simplify()}{Environment.NewLine}{Environment.NewLine}" +
                        $"res_dec : {res_dec}{Environment.NewLine}{Environment.NewLine}" +
                        $"epsilon : {epsilon}{Environment.NewLine}{Environment.NewLine}" +
                        $"res_dec - (a + k) : {BigFraction.Abs(res_dec - (a + k))}{Environment.NewLine}{Environment.NewLine}");
                }
            }
        }

        [Fact(DisplayName = "PLAINTEXT (Mul)")]
        public void TestPlaintextMul()
        {
            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    var algorithm = new Paillier(keySize);

                    var encryptAlgorithm = new Paillier(algorithm.ToXmlString(false));
                    var decryptAlgorithm = new Paillier(algorithm.ToXmlString(true));

                    var an = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                    var ad = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 4), rng);
                    var a = new BigFraction(an, ad);
                    if (rnd.Next() % 2 == 0) // randomly change signs
                        a = -a;

                    var a_enc = encryptAlgorithm.EncryptData(a);

                    var k = new BigInteger().GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits / 8), rng);

                    var res = algorithm.PlaintextMultiply(a_enc, k);

                    var res_dec = decryptAlgorithm.DecryptData(res);

                    var epsilon = new BigFraction(k, algorithm.PlaintextExp);
                    Assert.True(BigFraction.Abs(res_dec - (a * k)) <= epsilon,
                        $"{Environment.NewLine}{Environment.NewLine}" +
                        $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                        $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                        $"a       : {a}{Environment.NewLine}{Environment.NewLine}" +
                        $"k       : {k}{Environment.NewLine}{Environment.NewLine}" +
                        $"a * k   : {(a * k).Simplify()}{Environment.NewLine}{Environment.NewLine}" +
                        $"res_dec : {res_dec}{Environment.NewLine}{Environment.NewLine}" +
                        $"epsilon : {epsilon}{Environment.NewLine}{Environment.NewLine}" +
                        $"res_dec - (a * k) : {BigFraction.Abs(res_dec - a * k).Simplify()}{Environment.NewLine}{Environment.NewLine}");
                }
            }
        }
    }
}
