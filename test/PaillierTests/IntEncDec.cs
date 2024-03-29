﻿using System;
using System.Numerics;
using System.Security.Cryptography;
using Aprismatic;
using Aprismatic.Paillier;
using Xunit;
using Xunit.Abstractions;

namespace PaillierTests
{
    public class IntEncDec : IDisposable
    {
        private readonly ITestOutputHelper output;

        private readonly Random rnd = new Random();
        private readonly RandomNumberGenerator rng = new RNGCryptoServiceProvider();

        private readonly int minKeySize;
        private readonly int maxKeySize;
        private readonly int step;

        public IntEncDec(ITestOutputHelper output)
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

        [Fact(DisplayName = "INT (ENC/DEC, +-)")]
        public void TestRandomBigInteger()
        {
            for (var i = 0; i < Globals.iterations; i++)
            {
                for (var keySize = minKeySize; keySize <= maxKeySize; keySize += step)
                {
                    var algorithm = new Paillier(keySize);

                    var encryptAlgorithm = new Paillier(algorithm.ToXmlString(false));

                    var decryptAlgorithm = new Paillier(algorithm.ToXmlString(true));

                    var z = new BigInteger();

                    z = z.GenRandomBits(rnd.Next(1, algorithm.MaxPlaintextBits - 1), rng);
                    if (rnd.Next() % 2 == 0) // random sign
                        z = -z;

                    var z_enc = encryptAlgorithm.EncryptData(z);
                    var z_dec = decryptAlgorithm.DecryptData(z_enc);

                    Assert.True(z == z_dec, $"{Environment.NewLine}{Environment.NewLine}" +
                                            $"Algorithm parameters (TRUE):{Environment.NewLine}" +
                                            $"{algorithm.ToXmlString(true)}{Environment.NewLine}{Environment.NewLine}" +
                                            $"z     : {z}{Environment.NewLine}{Environment.NewLine}" +
                                            $"z_dec : {z_dec}");

                    algorithm.Dispose();
                    encryptAlgorithm.Dispose();
                    decryptAlgorithm.Dispose();
                }
            }
        }
    }
}
