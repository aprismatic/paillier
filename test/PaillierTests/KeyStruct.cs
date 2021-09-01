using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.PaillierExt;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class KeyStruct : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public KeyStruct(ITestOutputHelper output)
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

        [Fact(DisplayName = "Lengths")]
        public void TestLengths()
        {
            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    var algorithm = new Paillier(keySize);
                    var prms = algorithm.ExportParameters(false);
                    var bi = new BigInteger(prms.N);

                    Assert.Equal(algorithm.KeySize / 8, (bi.BitCount() + 7) / 8);

                    algorithm.Dispose();
                }
            }
        }
    }
}
