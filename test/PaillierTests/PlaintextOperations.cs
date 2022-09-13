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

        [Fact(DisplayName = "Egg timer")]
        public void TestEggTimer()
        {
            var paillier = new Paillier(512); // generate a new key pair
            var public_key = paillier.ToXmlString(false); // export public key

            // Encrypt 08:15 AM
            var h = paillier.EncryptData(08);
            var m = paillier.EncryptData(15);

            var eggTimeEnc = egg_timer(h, m, public_key); // <- we call the homomorphic circuit

            var eggTime = paillier.DecryptData(eggTimeEnc); // decrypt the result

            // check that everything was computed correctly
            Assert.Equal(501, eggTime); // 08:15 AM + 6 minutes = 495 minutes + 6 minutes = 501 minutes
        }

        // Here is the homomorphic circuit for our egg timer. Note that it never sees the plaintext values or
        // the private key. It can be executed in untrusted environment (at least under honest-but-curious model).
        public static byte[] egg_timer(byte[] h, byte[] m, string publicKeyXml)
        {
            var paillier = new Paillier(publicKeyXml);

            var h2m = paillier.PlaintextMultiply(h, 60); // hours to minutes
            var totalMinutesSinceMidnight = paillier.Add(h2m, m); // add minutes

            var eggTime = paillier.PlaintextAdd(totalMinutesSinceMidnight, 6); // add six minutes

            return eggTime;
        }
    }
}
