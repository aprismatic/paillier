/************************************************************************************
 This is an implementation of the Paillier encryption scheme with support for
 homomorphic addition.

 This library is provided as-is and is covered by the MIT License [1].

 [1] The MIT License (MIT), website, (http://opensource.org/licenses/MIT)
 ************************************************************************************/

using System;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Numerics;

namespace PaillierExtModified
{
    /*public enum PaillierPaddingMode : byte
    {
        ANSIX923,
        LeadingZeros,
        TrailingZeros,
        BigIntegerPadding
    }*/

    public abstract class PaillierModified : AsymmetricAlgorithm
    {
        //public PaillierPaddingMode Padding;

        public abstract void ImportParameters(PaillierParameters p_parameters);
        public abstract PaillierParameters ExportParameters(bool p_include_private_params);
        public abstract byte[] EncryptData(BigInteger p_data);
        public abstract BigInteger DecryptData(byte[] p_data);
        public abstract byte[] Sign(byte[] p_hashcode);
        public abstract bool VerifySignature(byte[] p_hashcode, byte[] p_signature);

        public abstract byte[] Addition(byte[] p_first, byte[] p_second);

        public override string ToXmlString(bool p_include_private)
        {
            var x_params = ExportParameters(p_include_private);
            var x_sb = new StringBuilder();

            x_sb.Append("<PaillierKeyValue>");

            x_sb.Append("<N>" + Convert.ToBase64String(x_params.N) + "</N>");
            x_sb.Append("<G>" + Convert.ToBase64String(x_params.G) + "</G>");
            //x_sb.Append("<Padding>" + x_params.Padding.ToString() + "</Padding>");

            if (p_include_private)
            {
                x_sb.Append("<Lambda>" + Convert.ToBase64String(x_params.Lambda) + "</Lambda>");
                x_sb.Append("<Miu>" + Convert.ToBase64String(x_params.Miu) + "</Miu>");
            }

            x_sb.Append("</PaillierKeyValue>");

            return x_sb.ToString();
        }

        public override void FromXmlString(string p_string)
        {
            var x_params = new PaillierParameters();

            var keyValues = XDocument.Parse(p_string).Element("PaillierKeyValue");

            x_params.N = Convert.FromBase64String((String)keyValues.Element("N") ?? "");
            x_params.G = Convert.FromBase64String((String)keyValues.Element("G") ?? "");
            //x_params.Padding = (PaillierPaddingMode)Enum.Parse(typeof(PaillierPaddingMode), (String)keyValues.Element("Padding") ?? "");
            x_params.Lambda = Convert.FromBase64String((String)keyValues.Element("Lambda") ?? "");
            x_params.Miu = Convert.FromBase64String((String)keyValues.Element("Miu") ?? "");

            ImportParameters(x_params);
        }
    }
}
