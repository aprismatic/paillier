﻿using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Aprismatic.Paillier
{
    public class PaillierEncryptor : IDisposable
    {
        private readonly RandomNumberGenerator rng;
        private readonly PaillierKeyStruct _keyStruct;

        public PaillierEncryptor(PaillierKeyStruct keyStruct)
        {
            rng = RandomNumberGenerator.Create();
            _keyStruct = keyStruct;
        }

        public void ProcessBigInteger(BigInteger encodedMessage, BigInteger encodedMessage_neg, Span<byte> res)
        {
            BigInteger R;

            // generate random r ∊ Zn
            var NminusOne = _keyStruct.N - BigInteger.One;
            do
            {
                R = BigInteger.Zero.GenRandomBits(_keyStruct.NBitCount, rng);
            } while (R <= BigInteger.One || R >= NminusOne);

            // ciphertext c = g^m * r^N mod N²
            var RN = BigInteger.ModPow(R, _keyStruct.N, _keyStruct.NSquare);

            // if we use simple key generation (g = N + 1), we can use
            // (N+1)^m = N*m + 1  mod N²
            var Gm = (_keyStruct.N * encodedMessage + BigInteger.One) % _keyStruct.NSquare;
            var Gm_Neg = (_keyStruct.N * encodedMessage_neg + BigInteger.One) % _keyStruct.NSquare;

            var C = (Gm * RN) % _keyStruct.NSquare;
            var C_Neg = (Gm_Neg * RN) % _keyStruct.NSquare;

            var lgth = res.Length >> 1;
            C.TryWriteBytes(res[..lgth], out _);
            C_Neg.TryWriteBytes(res[lgth..], out _);
        }

        public void Dispose() => rng.Dispose();
    }
}
