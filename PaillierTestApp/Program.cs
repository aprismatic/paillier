using PaillierExt;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;


public class Test
{
    public static void Main()
    {
        TestTextEncryption();
        //TestAddition_Batch();
    }

    public static String PrettifyXML(String XML)
    {
        String Result = "";

        MemoryStream mStream = new MemoryStream();
        XmlTextWriter writer = new XmlTextWriter(mStream, Encoding.Unicode);
        XmlDocument document = new XmlDocument();

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
            StreamReader sReader = new StreamReader(mStream);

            // Extract the text from the StreamReader.
            String FormattedXML = sReader.ReadToEnd();

            Result = FormattedXML;
        }
        catch (XmlException)
        {
        }

        mStream.Close();
        writer.Close();

        return Result;
    }

    public static void TestTextEncryption(string message = "This is to test Paillier encryption and hopefully this message contains more than 2 blocks please please please please please please please please please please please pleaseplease please please pleaseplease please please please          ", 
        int keySize = 384, PaillierPaddingMode padding = PaillierPaddingMode.Zeros)
    {
        Console.WriteLine();
        Console.WriteLine("-- Testing string encryption ---");

        byte[] plaintext = Encoding.Default.GetBytes(message);

        Paillier algorithm = new PaillierManaged();

        algorithm.KeySize = keySize;
        algorithm.Padding = padding;

        string parametersXML = algorithm.ToXmlString(true);
        Console.WriteLine("\n{0}\n", PrettifyXML(parametersXML));

        Paillier encryptAlgorithm = new PaillierManaged();
        encryptAlgorithm.FromXmlString(algorithm.ToXmlString(false));

        byte[] ciphertext = encryptAlgorithm.EncryptData(plaintext);

        Paillier decryptAlgorithm = new PaillierManaged();
        decryptAlgorithm.FromXmlString(algorithm.ToXmlString(true));

        byte[] candidatePlaintext = decryptAlgorithm.DecryptData(ciphertext);

        byte[] strip_zeros = StripTrailingZeros(candidatePlaintext, plaintext.Length);

        Console.WriteLine("Original string:  '{0}'", message);
        Console.WriteLine("Decrypted string: '{0}'", Encoding.Default.GetString(candidatePlaintext));
        //Console.WriteLine("Byte arrays equal: {0}", plaintext.SequenceEqual(candidatePlaintext));
        Console.WriteLine("Byte arrays equal: {0}", plaintext.SequenceEqual(strip_zeros));
        Console.WriteLine();
    }

    public static void TestAddition_Batch()
    {
        int error_counter = 0;
        int iteration = 40;
        Console.WriteLine("-- Testing Addition Homomorphic property in batch---");

        for (int i = 0; i < iteration; i++)
        {
            if (!TestAddition())
            {
                error_counter++;
            }
        }
        Console.WriteLine();
        Console.WriteLine("There are {0} / {1} errors.", error_counter, iteration);
    }

    public static Boolean TestAddition()
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

        Random random = new Random();
        BigInteger A = new BigInteger(random.Next(32768));
        BigInteger B = new BigInteger(random.Next(32768));

        byte[] A_bytes = A.getBytes();
        byte[] B_bytes = B.getBytes();

        //encrypt A and B
        byte[] A_enc_bytes = encryptAlgorithm.EncryptData(A.getBytes());
        byte[] B_enc_bytes = encryptAlgorithm.EncryptData(B.getBytes());

        // decrypt A and B
        byte[] A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        byte[] B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        byte[] C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        byte[] C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // strip off trailing zeros
        //byte[] A_dec_stripped = StripTrailingZeros(A_dec_bytes, A_bytes.Length);
        //byte[] B_dec_stripped = StripTrailingZeros(B_dec_bytes, B_bytes.Length);
        //byte[] C_dec_stripped = StripTrailingZeros(C_dec_bytes);

        // convert to BigInteger
        BigInteger A_dec = new BigInteger(A_dec_bytes);
        BigInteger B_dec = new BigInteger(B_dec_bytes);
        BigInteger C_dec = new BigInteger(C_dec_bytes);

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
        byte[] array_stripped = new byte[arrayLength];

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

        byte[] array_stripped = new byte[i+1];
        Array.Copy(array, 0, array_stripped, 0, i+1);

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

        byte[] A_bytes = A.getBytes();
        byte[] B_bytes = B.getBytes();

        //encrypt A and B
        byte[] A_enc_bytes = encryptAlgorithm.EncryptData(A.getBytes());
        byte[] B_enc_bytes = encryptAlgorithm.EncryptData(B.getBytes());

        // decrypt A and B
        byte[] A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        byte[] B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        //getting homomorphic addition result
        byte[] C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        byte[] C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        BigInteger A_dec = new BigInteger(A_dec_bytes);
        BigInteger B_dec = new BigInteger(B_dec_bytes);
        BigInteger C_dec = new BigInteger(C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A + B).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }

    public static void Rerun_SameKey(Paillier encryptAlgorithm, Paillier decryptAlgorithm)
    {
        Random random = new Random();
        BigInteger A = new BigInteger(random.Next(32768));
        BigInteger B = new BigInteger(random.Next(32768));

        byte[] A_bytes = A.getBytes();
        byte[] B_bytes = B.getBytes();

        //encrypt A and B
        byte[] A_enc_bytes = encryptAlgorithm.EncryptData(A.getBytes());
        byte[] B_enc_bytes = encryptAlgorithm.EncryptData(B.getBytes());

        // decrypt A and B
        byte[] A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        byte[] B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        byte[] C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        byte[] C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        BigInteger A_dec = new BigInteger(A_dec_bytes);
        BigInteger B_dec = new BigInteger(B_dec_bytes);
        BigInteger C_dec = new BigInteger(C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A + B).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }

    public static void Rerun_SamekeyNumber(Paillier encryptAlgorithm, Paillier decryptAlgorithm,
        BigInteger A, BigInteger B)
    {
        byte[] A_bytes = A.getBytes();
        byte[] B_bytes = B.getBytes();

        //encrypt A and B
        byte[] A_enc_bytes = encryptAlgorithm.EncryptData(A.getBytes());
        byte[] B_enc_bytes = encryptAlgorithm.EncryptData(B.getBytes());

        // decrypt A and B
        byte[] A_dec_bytes = decryptAlgorithm.DecryptData(A_enc_bytes);
        byte[] B_dec_bytes = decryptAlgorithm.DecryptData(B_enc_bytes);

        // getting homomorphic addition result
        byte[] C_enc_bytes = encryptAlgorithm.Addition(A_enc_bytes, B_enc_bytes);
        byte[] C_dec_bytes = decryptAlgorithm.DecryptData(C_enc_bytes);

        // convert to BigInteger
        BigInteger A_dec = new BigInteger(A_dec_bytes);
        BigInteger B_dec = new BigInteger(B_dec_bytes);
        BigInteger C_dec = new BigInteger(C_dec_bytes);

        // printing out
        Console.WriteLine("Plaintext: {0} + {1} = {2}", A.ToString(), B.ToString(), (A + B).ToString());
        Console.WriteLine("Encrypted: {0} + {1} = {2}", A_dec.ToString(), B_dec.ToString(), C_dec.ToString());
    }
}

