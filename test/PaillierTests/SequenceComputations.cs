using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.Paillier;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class SequenceComputations : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new();
        private readonly RandomNumberGenerator rng = RandomNumberGenerator.Create();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public SequenceComputations(ITestOutputHelper output)
        {
            this.output = output;

            using var tmpElG = new Paillier(512);
            minKeySize = tmpElG.LegalKeySizes[0].MinSize;
            maxKeySize = tmpElG.LegalKeySizes[0].MaxSize;
            step = (maxKeySize - minKeySize) / tmpElG.LegalKeySizes[0].SkipSize;
        }

        public void Dispose() => rng.Dispose();

        [Fact(DisplayName = "Egg timer")]
        public void TestEggTimer()
        {
            var paillier = new Paillier(512); // generate a new key pair
            var public_key = paillier.ToXmlString(false); // export public key

            // Encrypt 08:15 AM
            var h = paillier.EncryptData(08);
            var m = paillier.EncryptData(15);

            var eggTimeEnc = add_six_hm_homomorphic(h, m, public_key); // <- we call the homomorphic circuit

            var eggTime = paillier.DecryptData(eggTimeEnc); // decrypt the result

            // check that everything was computed correctly
            Assert.Equal(501, eggTime); // 08:15 AM + 6 minutes = 495 minutes + 6 minutes = 501 minutes
        }

        // Here is the homomorphic circuit for our egg timer. Note that it never sees the plaintext values or
        // the private key. It can be executed in untrusted environment (at least under honest-but-curious model).
        public static byte[] add_six_hm_homomorphic(byte[] h, byte[] m, string publicKeyXml)
        {
            var paillier = new Paillier(publicKeyXml);

            var h2m = paillier.PlaintextMultiply(h, 60); // hours to minutes
            var totalMinutesSinceMidnight = paillier.Add(h2m, m); // add minutes
            var eggTime = paillier.PlaintextAdd(totalMinutesSinceMidnight, 6); // add six minutes

            return eggTime;
        }
    }
}
