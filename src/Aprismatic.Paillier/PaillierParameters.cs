using System;
using System.Numerics;
using System.Text;
using System.Xml.Linq;

namespace Aprismatic.Paillier
{
    [Serializable]
    public struct PaillierParameters
    {
        // public portion
        public byte[] N;
        public byte[] G;
        public int PlaintextDecPlace;
        public int MaxPlaintextBits;

        // private portion
        public byte[] Lambda;
        public byte[] Mu;

        // TODO: Add logic for key format versioning
        // TODO: Consider adding support for ASN.1/PKCS format
        public static PaillierParameters FromXml(string Xml)
        {
            var res = new PaillierParameters();

            var kv = XDocument.Parse(Xml).Element("PaillierKeyValue");

            // PARSE THE PUBLIC KEY PORTION
            var kvelN = kv.Element("N");
            if (kvelN == null)
                throw new ArgumentException("Provided XML does not have a public key value N");
            res.N = Convert.FromBase64String(kvelN.Value);

            var kvelG = kv.Element("G");
            if (kvelG == null)
                throw new ArgumentException("Provided XML does not have a public key value G");
            res.G = Convert.FromBase64String(kvelG.Value);

            var kvelPDP = kv.Element("PlaintextDecPlace");
            res.PlaintextDecPlace = kvelPDP != null ? int.Parse(kvelPDP.Value) : PaillierKeyDefaults.DefaultPlaintextDecPlace;

            var kvelMPB = kv.Element("MaxPlaintextBits");
            res.MaxPlaintextBits = kvelMPB != null ? int.Parse(kvelMPB.Value) : PaillierKeyDefaults.DefaultMaxPlaintextBits;

            // PARSE THE PRIVATE KEY PORTION
            var kvelLambda = kv.Element("Lambda");
            res.Lambda = kvelLambda == null ? BigInteger.Zero.ToByteArray() : Convert.FromBase64String(kvelLambda.Value);

            var kvelMu = kv.Element("Mu");
            res.Mu = kvelMu == null ? BigInteger.Zero.ToByteArray() : Convert.FromBase64String(kvelMu.Value);

            return res;
        }

        public string ToXml(bool includePrivateParameters)
        {
            var sb = new StringBuilder();

            sb.Append("<PaillierKeyValue>");

            sb.Append("<N>" + Convert.ToBase64String(N) + "</N>");
            sb.Append("<G>" + Convert.ToBase64String(G) + "</G>");
            sb.Append("<MaxPlaintextBits>" + MaxPlaintextBits.ToString() + "</MaxPlaintextBits>");
            sb.Append("<PlaintextDecPlace>" + PlaintextDecPlace.ToString() + "</PlaintextDecPlace>");

            if (includePrivateParameters)
            {
                sb.Append("<Lambda>" + Convert.ToBase64String(Lambda) + "</Lambda>");
                sb.Append("<Mu>" + Convert.ToBase64String(Mu) + "</Mu>");
            }

            sb.Append("</PaillierKeyValue>");

            return sb.ToString();
        }
    }
}
