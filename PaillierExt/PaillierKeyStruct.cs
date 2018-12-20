using System.Numerics;

namespace Aprismatic.PaillierExt
{
    public struct PaillierKeyStruct
    {
        private BigInteger _n;

        public BigInteger N
        {
            get => _n;
            set
            {
                _n = value;
                NSquare = _n * _n;
            }
        }
        public BigInteger NSquare { get; private set; }

        public BigInteger G;
        public BigInteger Lambda;
        public BigInteger Miu;

        private BigInteger _maxRawPT;
        public BigInteger MaxRawPlaintext
        {
            get
            {
                if (_maxRawPT == BigInteger.Zero)
                    _maxRawPT = BigInteger.Pow(2, getMaxPlaintextBits()) - BigInteger.One;
                return _maxRawPT;
            }
        }

        private BigInteger _maxRawPT_half;
        public BigInteger MaxEncryptableValue
        {
            get
            {
                if (_maxRawPT_half == BigInteger.Zero)
                    _maxRawPT_half = MaxRawPlaintext / 2;
                return _maxRawPT_half;
            }
        }


        private BigInteger _PTExp;
        public BigInteger PlaintextExp
        {
            get
            {
                if (_PTExp == BigInteger.Zero)
                    _PTExp = BigInteger.Pow(10, getPlaintextDecPlace());
                return _PTExp;
            }
        }

        public int getMaxPlaintextBits()
        {
            return 128; // 128 bit 
        }

        public int getPlaintextDecPlace()
        {
            return 12; // 12 decimal places allowed in plain text
        }

        public int getCiphertextBlocksize()
        {
            return getNLength() * 2 + 2;
        }

        public int getCiphertextLength()
        {
            return getCiphertextBlocksize() * 2;
        }

        public int getNLength()
        {
            return (_n.BitCount() + 7) / 8;
        }

        public int getNSquareLength()
        {
            return getNLength() * 2;
        }
    }
}
