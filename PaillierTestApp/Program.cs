using PaillierExt;

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;


public class Test
{
    public static void Main()
    {
        //TestTextEncryption();
        //TestAddition_Batch();
        PerformanceTest();
        //TestZero();
        //TestRandomBI();
    }

    private static void TestZero()
    {
        Paillier algorithm = new PaillierManaged();
        algorithm.KeySize = 384;
        algorithm.Padding = PaillierPaddingMode.LeadingZeros;

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        var z = new BigInteger(0);

        var z_enc = encryptAlgorithm.EncryptData(z.getBytes());

        for (int i = 0; i < z_enc.Length; i++)
        {
            Console.Write(z_enc[i]);
        }
        Console.WriteLine();

        var z_dec = decryptAlgorithm.DecryptData(z_enc);

        for (int i = 0; i < z_dec.Length; i++)
        {
            Console.Write(z_dec[i]);
        }
        Console.WriteLine();
    }

    public static void TestRandomBI()
    {
        // To inspect the output, no idea why random number of zeroes appear in between decrypted bytes
        // The original bytes and decrypted bytes are the same without zeroes
        // Run several times, the appearance of zeroes seems unpredictale
        Paillier algorithm = new PaillierManaged();
        algorithm.Padding = PaillierPaddingMode.LeadingZeros;

        algorithm.KeySize = 384;
        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        var z = new BigInteger();
        var randomBit = new Random().Next(1, 2241);
        z.genRandomBits(randomBit, new RNGCryptoServiceProvider());

        var z_enc = encryptAlgorithm.EncryptData(z.getBytes());
        var z_dec = decryptAlgorithm.DecryptData(z_enc);

        for (int i = 0; i < z.getBytes().Length; i++)
        {
            Console.Write(z.getBytes()[i]);
        }
        Console.WriteLine();
        int zeroCounter = z_dec.Length - z.getBytes().Length;
        for (int i = 0; i < z_dec.Length; i++)
        {
            Console.Write(z_dec[i]);
        }
        Console.WriteLine();
        Console.WriteLine
            ("Number of zero: {0}" +
            "\nNumber of original bytes: {1}" + 
            "\nNumber of decrypted bytes: {2}" +
            "\nNumber of bits used to gen random bytes: {3}"
            ,zeroCounter, z.getBytes().Length, z_dec.Length, randomBit);
    }

    public static string PrettifyXML(string XML)
    {
        var res = "";

        using (var mStream = new MemoryStream())
        {
            using (var writer = new XmlTextWriter(mStream, Encoding.Unicode))
            {
                var document = new XmlDocument();

                try
                {
                    // Load the XmlDocument with the XML.
                    document.LoadXml(XML);

                    writer.Formatting = Formatting.Indented;

                    // Write the XML into a formatting XmlTextWriter
                    document.WriteContentTo(writer);
                    writer.Flush();
                    mStream.Flush();

                    // Have to rewind the MemoryStream in order to read
                    // its contents.
                    mStream.Position = 0;

                    // Read MemoryStream contents into a StreamReader.
                    using (var sReader = new StreamReader(mStream))
                    {

                        // Extract the text from the StreamReader.
                        var FormattedXML = sReader.ReadToEnd();

                        res = FormattedXML;
                    }
                }
                catch (XmlException)
                {
                }

                mStream.Close();
                writer.Close();
            }
        }

        return res;
    }

    public static void TestTextEncryption(string message = "This is to test Paillier encryption and hopefully this message contains more than 2 blocks please please please please please please please please please please please pleaseplease please please pleaseplease please please please          ",
        int keySize = 384, PaillierPaddingMode padding = PaillierPaddingMode.Zeros)
    {
        Console.WriteLine();
        Console.WriteLine("-- Testing string encryption ---");

        var plaintext = Encoding.Default.GetBytes(message);

        Paillier algorithm = new PaillierManaged();

        algorithm.KeySize = keySize;
        algorithm.Padding = padding;

        var parametersXML = algorithm.ToXmlString(true);
        Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        var ciphertext = encryptAlgorithm.EncryptData(plaintext);

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        var candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

        var strip_zeros = StripTrailingZeros(candidatePlaintext, plaintext.Length);

        Console.WriteLine("Original string:  '{0}'", message);
        Console.WriteLine("Decrypted string: '{0}'", Encoding.Default.GetString(candidatePlaintext));
        //Console.WriteLine("Byte arrays equal: {0}", plaintext.SequenceEqual(candidatePlaintext));
        Console.WriteLine("Byte arrays equal: {0}", plaintext.SequenceEqual(strip_zeros));
        Console.WriteLine();
    }

    public static void TestAddition_Batch()
    {
        var error_counter = 0;
        var iteration = 40;
        Console.WriteLine("-- Testing Addition Homomorphic property in batch---");

        for (var i = 0; i < iteration; i++)
        {
            if (!TestAddition())
            {
                error_counter++;
            }
        }
        Console.WriteLine();
        Console.WriteLine("There are {0} / {1} errors.", error_counter, iteration);
    }

    public static bool TestAddition()
    {
        Paillier algorithm = new PaillierManaged();
        algorithm.KeySize = 384;
        algorithm.Padding = PaillierPaddingMode.LeadingZeros;

        string parametersXML = algorithm.ToXmlString(true);

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        var random = new Random();
        var A = new BigInteger(random.Next(32768));
        var B = new BigInteger(random.Next(32768));

        var A_bytes = A.getBytes();
        var B_bytes = B.getBytes();

        //encrypt A and B
        var A_enc_bytes = encryptAlgorithm.EncryptData(A_bytes);
        var B_enc_bytes = encryptAlgorithm.EncryptData(B_bytes);

        // decrypt A and B
        var A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        var B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        var C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        var A_dec = new BigInteger(A_dec_bytes);
        var B_dec = new BigInteger(B_dec_bytes);
        var C_dec = new BigInteger(C_dec_bytes);

        if (C_dec != A + B)
        {
            Console.WriteLine();
            Console.WriteLine("***********Error Encountered!!***");
            Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));
            // printing out
            Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A + B).ToString());
            Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
            Console.WriteLine();

            Console.WriteLine("Re-run the numbers with different key..");
            Rerun_SameNumbers(A, B);
            Console.WriteLine();

            Console.WriteLine("Re-run the same key with different numbers..");
            Rerun_SameKey(encryptAlgorithm, decryptAlgorithm);
            Console.WriteLine();

            Console.WriteLine("Re-run with same key and same numbers..");
            Rerun_SamekeyNumber(encryptAlgorithm, decryptAlgorithm, A, B);
            Console.WriteLine();

            return false;
        }
        return true;
    }

    public static byte[] StripTrailingZeros(byte[] array, int arrayLength)
    {
        var array_stripped = new byte[arrayLength];

        Array.Copy(array, 0, array_stripped, 0, arrayLength);

        return array_stripped;
    }

    public static byte[] StripTrailingZeros(byte[] array)
    {
        var i = array.Length - 1;
        while (array[i] == 0)
        {
            i--;
        }

        byte[] array_stripped = new byte[i + 1];
        Array.Copy(array, 0, array_stripped, 0, i + 1);

        return array_stripped;
    }

    public static void Rerun_SameNumbers(BigInteger A, BigInteger B)
    {
        Paillier algorithm = new PaillierManaged();
        algorithm.KeySize = 384;
        algorithm.Padding = PaillierPaddingMode.LeadingZeros;

        string parametersXML = algorithm.ToXmlString(true);
        //Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        var A_bytes = A.getBytes();
        var B_bytes = B.getBytes();

        //encrypt A and B
        var A_enc_bytes = encryptAlgorithm.EncryptData(A.getBytes());
        var B_enc_bytes = encryptAlgorithm.EncryptData(B.getBytes());

        // decrypt A and B
        var A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        var B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        //getting homomorphic addition result
        var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        var C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        var A_dec = new BigInteger(A_dec_bytes);
        var B_dec = new BigInteger(B_dec_bytes);
        var C_dec = new BigInteger(C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A + B).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }

    public static void Rerun_SameKey(Paillier encryptAlgorithm, Paillier decryptAlgorithm)
    {
        var random = new Random();
        var A = new BigInteger(random.Next(32768));
        var B = new BigInteger(random.Next(32768));

        var A_bytes = A.getBytes();
        var B_bytes = B.getBytes();

        //encrypt A and B
        var A_enc_bytes = encryptAlgorithm.EncryptData(A.getBytes());
        var B_enc_bytes = encryptAlgorithm.EncryptData(B.getBytes());

        // decrypt A and B
        var A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        var B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        var C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        var A_dec = new BigInteger(A_dec_bytes);
        var B_dec = new BigInteger(B_dec_bytes);
        var C_dec = new BigInteger(C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A + B).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }

    public static void Rerun_SamekeyNumber(Paillier encryptAlgorithm, Paillier decryptAlgorithm, BigInteger A, BigInteger B)
    {
        var A_bytes = A.getBytes();
        var B_bytes = B.getBytes();

        //encrypt A and B
        var A_enc_bytes = encryptAlgorithm.EncryptData(A.getBytes());
        var B_enc_bytes = encryptAlgorithm.EncryptData(B.getBytes());

        // decrypt A and B
        var A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        var B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        var C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        var C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        var A_dec = new BigInteger(A_dec_bytes);
        var B_dec = new BigInteger(B_dec_bytes);
        var C_dec = new BigInteger(C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A + B).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }

    public static void PerformanceTest()
    {
        Console.WriteLine();

        int[] bits = { 384, 512, 640, 768, 896, 1024 };

        foreach (var keyl in bits)
        {
            Console.WriteLine("-- Performance Test -- {0} bits --", keyl);

            long total_time_plaintext = 0;
            long total_time_encrypted = 0;

            for (var i = 0; i < 12; i++)
            {
                //Console.WriteLine("-- Performance test iteration {0} --", i);

                total_time_plaintext += ProfilePlaintextADD(250000);
                total_time_encrypted += ProfileEncryptedADD(250000, keyl);
            }

            Console.WriteLine("Total time for plaintext multiplication  = {0} ticks", total_time_plaintext);
            Console.WriteLine("Total time for ciphertext multiplication = {0} ticks", total_time_encrypted);
            Console.WriteLine();
        }
    }

    private static long ProfilePlaintextADD(int iterations)
    {
        // clean up
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var rnd = new Random();

        // prepare and warm up 
        var a = (Int64)rnd.Next(65536);
        var b = (Int64)rnd.Next(65536);
        var c = a * b;

        var watch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            c = a + b;
        }
        watch.Stop();

        return watch.Elapsed.Ticks;
    }

    private static long ProfileEncryptedADD(int iterations, int keyl)
    {
        // clean up
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        var rnd = new Random();

        // prepare and warm up 
        Paillier algorithm = new PaillierManaged();
        algorithm.KeySize = keyl;
        algorithm.Padding = PaillierPaddingMode.LeadingZeros;
        //string parametersXML = algorithm.ToXmlString(true);

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        var a = new BigInteger(rnd.Next(65536));
        var a_bytes = encryptAlgorithm.EncryptData(a.getBytes());

        var b = new BigInteger(rnd.Next(65536));
        var b_bytes = encryptAlgorithm.EncryptData(b.getBytes());

        var c_bytes = encryptAlgorithm.Addition(a_bytes, b_bytes);

        var watch = Stopwatch.StartNew();
        for (int i = 0; i < iterations; i++)
        {
            c_bytes = encryptAlgorithm.Addition(a_bytes, b_bytes);
        }
        watch.Stop();

        return watch.Elapsed.Ticks;
    }
}
