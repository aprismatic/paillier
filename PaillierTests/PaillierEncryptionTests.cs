using BigIntegerExt;
using PaillierExt;
using System;
using System.Numerics;
using System.Security.Cryptography;
using Xunit;
using Numerics;

namespace PaillierTests
{
    public class PaillierEncryptionTests
    {
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
                var z_enc_bytes = encryptAlgorithm.EncryptData(z);
                var z_dec = decryptAlgorithm.DecryptData(z_enc_bytes);
                Assert.Equal(z, z_dec);
            }
        }

        [Fact(DisplayName = "Random BigIntegers")]
        public void TestRandomBigIntegers()
        {
            var iterations = 10;
            var rnd = new Random();
            var rng = new RNGCryptoServiceProvider();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                for (var i = 0; i < iterations; i++)
                {
                    var algorithm = new Paillier
                    {
                        KeySize = keySize
                    };

                    var encryptAlgorithm = new Paillier();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    var decryptAlgorithm = new Paillier();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var z = new BigInteger();

                    // Plaintext that is bigger than one block requires different padding (e.g. ANSIX923 or PKCS97)
                    z = z.GenRandomBits(rnd.Next(2, (algorithm as Paillier).KeyStruct.getPlaintextBlocksize() * 8), rng);

                    var z_enc_bytes = encryptAlgorithm.EncryptData(z);
                    var z_dec = decryptAlgorithm.DecryptData(z_enc_bytes);

                    Assert.Equal(z, z_dec);
                }
            }
        }


        [Fact(DisplayName = "Specific cases")]
        public void TestSpecificCases()
        {
            {
                var algorithm = new Paillier
                {
                    KeySize = 384
                };

                var z = new BigInteger(138);

                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);

                Assert.Equal(z, z_dec);
            }
        }

        [Fact(DisplayName = "Addition batch")]
        public void TestAddition_Batch()
        {
            var iterations = 10;
            var random = new Random();

            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                for (var i = 0; i < iterations; i++)
                {
                    var algorithm = new Paillier
                    {
                        KeySize = keySize
                    };

                    var encryptAlgorithm = new Paillier();
                    encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

                    var decryptAlgorithm = new Paillier();
                    decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

                    var A = new BigInteger(random.Next());
                    var B = new BigInteger(random.Next());

                    //encrypt A and B
                    var A_enc_bytes = encryptAlgorithm.EncryptData(A);
                    var B_enc_bytes = encryptAlgorithm.EncryptData(B);

                    // getting homomorphic addition result
                    var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
                    var C_dec = decryptAlgorithm.DecryptData(C_enc_bytes);


                    Assert.True(A + B == C_dec, $"Key length: {keySize}{Environment.NewLine}" +
                                                $"A:          {A}{Environment.NewLine}" +
                                                $"B:          {B}{Environment.NewLine}" +
                                                $"A + B:      {A + B}{Environment.NewLine}" +
                                                $"C_dec:      {C_dec}");
                }
            }
        }

        [Fact(DisplayName = "From issue #15")]
        public void Test_FromIssue_15() // based on https://github.com/bazzilic/PaillierExt/issues/15
        {
            for (var keySize = 384; keySize <= 1088; keySize += 8)
            {
                var algorithm = new Paillier
                {
                    KeySize = keySize
                };

                var sum = algorithm.EncryptData(new BigInteger(0));
                var one = algorithm.EncryptData(new BigInteger(1));

                for (var i = 0; i < 1000; i++)
                {
                    sum = algorithm.Addition(sum, one);
                }

                var sums = algorithm.DecryptData(sum);

                Assert.Equal(new BigInteger(1000), sums);
            }
        }

        [Fact(DisplayName = "Negative cases")]
        public void TestNegativeCases()
        {
            {
                var algorithm = new Paillier
                {
                    KeySize = 384
                };

                var z = new BigInteger(-6);
                var z_enc_bytes = algorithm.EncryptData(z);
                var z_dec = algorithm.DecryptData(z_enc_bytes);
                Assert.Equal(z, z_dec);


                var z_2 = new BigInteger(4);
                var z_enc_bytes_2 = algorithm.EncryptData(z_2);
                var z_dec_2 = algorithm.DecryptData(z_enc_bytes_2);
                Assert.Equal(z_2, z_dec_2);

                var z_enc_addition = algorithm.Addition(z_enc_bytes, z_enc_bytes_2);
                var z_addition = algorithm.DecryptData(z_enc_addition);
                Assert.Equal(z + z_2, z_addition);
            }
        }

		[Fact(DisplayName = "Floating point")]
		public void TestFloatingPoint()
		{
			{
				var algorithm = new Paillier
				{
					KeySize = 384
				};

				/**
				 *Test 1 decimal place

				 **/

				var z = new BigRational(new Decimal(0.1));

				//Convert fraction to whole number. Denominator will be the exponent
				var z_whole = z.Numerator;
				var z_exponent = z.Denominator;

				//Encrypt and decrypt
				var z_enc_bytes = algorithm.EncryptData(z_whole);
				var z_dec = algorithm.DecryptData(z_enc_bytes);

				//Reconvert back to fraction
				var z_dec_float = new BigRational(z_dec, z_exponent);

				Assert.Equal(z, z_dec_float);




				/**
				 *Test 2 decimal places

				 **/

				var z_2 = new BigRational(new Decimal(0.02));

				//Convert fraction to whole number. Denominator will be the exponent
				var z_2_whole = z_2.Numerator;
				var z_2_exponent = z_2.Denominator;

				//Encrypt and decrypt
				var z_enc_bytes_2 = algorithm.EncryptData(z_2_whole);
				var z_dec_2 = algorithm.DecryptData(z_enc_bytes_2);

				//Reconvert back to fraction
				var z_dec_2_float = new BigRational(z_dec_2, z_2_exponent);

				Assert.Equal(z_2, z_dec_2_float);



				/**
                 *  Test addition of 2 floats with different decimal places
                 * */

				z = new BigRational(new Decimal(0.1));
				z_2 = new BigRational(new Decimal(0.02));

				//For addition, the exponent of both plain text needs to be the same
				var common_exponent = new BigInteger(1);

				//The larger exponent among the 2 floats will be used as the common exponent
				if (z.Denominator.CompareTo(z_2.Denominator) == 1)
				{
					common_exponent = z.Denominator;
				}
				else
				{
					common_exponent = z_2.Denominator;
				}

				//Convert fraction to whole number
				z_whole = z.Numerator * (common_exponent / z.Denominator);
				z_2_whole = z_2.Numerator * (common_exponent / z_2.Denominator);

				//Encrypt
				z_enc_bytes = algorithm.EncryptData(z_whole);
				z_enc_bytes_2 = algorithm.EncryptData(z_2_whole);

				//Addition
				var z_enc_addition = algorithm.Addition(z_enc_bytes, z_enc_bytes_2);

				//Decrypt
				var z_addition = algorithm.DecryptData(z_enc_addition);

				//Convert to fraction
				var z_addition_fraction = new BigRational(z_addition, common_exponent);

				Assert.Equal(z + z_2, z_addition_fraction);
			}
		}
	}
}
