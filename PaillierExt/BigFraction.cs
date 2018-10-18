using System;
using System.Numerics;

namespace PaillierExt
{
    public struct BigFraction
    {
        //Paramaters Numerator / Denominator
        public BigInteger Numerator { get; private set; }
        public BigInteger Denominator { get; private set; }

        //CONSTRUCTORS

        //Fractional constructor
        public BigFraction(BigInteger num, BigInteger den)
        {
            Numerator = num;
            Denominator = den;
        }

        //BigInteger constructor
        public BigFraction(BigInteger num)
        {
            Numerator = num;
            Denominator = BigInteger.One;
        }

        //Decimal constructor
        public BigFraction(decimal dec)
        {
            int count = BitConverter.GetBytes(decimal.GetBits(dec)[3])[2];  //count decimal places
            Numerator = new BigInteger(dec * (Decimal)Math.Pow(10, count));
            Denominator = new BigInteger(Math.Pow(10, count));
        }

        //Double constructor
        public BigFraction(double dou, double accuracy = 1e-15)
        {
            BigFraction f = FromDouble(dou, accuracy);
            Numerator = f.Numerator;
            Denominator = f.Denominator;
        }

        //Integer constructor
        public BigFraction(int i)
        {
            Numerator = new BigInteger(i);
            Denominator = BigInteger.One;
        }

        //OPERATORS

        //User-defined conversion from BigInteger to BigFraction
        public static implicit operator BigFraction(BigInteger integer)
        {
            return new BigFraction(integer);
        }

        //User-defined conversion from Decimal to BigFraction
        public static implicit operator BigFraction(decimal dec)
        {
            return new BigFraction(dec);
        }

        //User-defined conversion from Double to BigFraction
        public static implicit operator BigFraction(double d)
        {
            return new BigFraction(d);
        }

        //User-defined conversion from Integer to BigFraction
        public static implicit operator BigFraction(int i)
        {
            return new BigFraction(i);
        }

        //Operator %
        public static BigFraction operator %(BigFraction r, BigInteger mod)
        {
            BigInteger modmulden = r.Denominator * mod;
            BigInteger remainder = r.Numerator % modmulden;
            BigFraction answer = new BigFraction(remainder, r.Denominator);
            return answer;
        }

        //Operator >
        public static Boolean operator >(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == 1) { return true; }
            else { return false; }
        }

        //Operator <
        public static Boolean operator <(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == -1) { return true; }
            else { return false; }
        }

        //Operator ==
        public static Boolean operator ==(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == 0) { return true; }
            else { return false; }
        }

        //Operator !=
        public static Boolean operator !=(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == 0) { return false; }
            else { return true; }
        }

        //Operator <=
        public static Boolean operator <=(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == -1 || r1compare.CompareTo(r2compare) == 0) { return true; }
            else { return false; }
        }

        //Operator >=
        public static Boolean operator >=(BigFraction r1, BigFraction r2)
        {
            BigInteger r1compare = r1.Numerator * r2.Denominator;
            BigInteger r2compare = r2.Numerator * r1.Denominator;
            if (r1compare.CompareTo(r2compare) == 1 || r1compare.CompareTo(r2compare) == 0) { return true; }
            else { return false; }
        }

        //Operator -
        public static BigFraction operator -(BigFraction a, BigFraction b)
        {
            a.Numerator = a.Numerator * b.Denominator - b.Numerator * a.Denominator;
            a.Denominator = a.Denominator * b.Denominator;
            return a;
        }

        //Operator +
        public static BigFraction operator +(BigFraction a, BigFraction b)
        {
            a.Numerator = a.Numerator * b.Denominator + b.Numerator * a.Denominator;
            a.Denominator = a.Denominator * b.Denominator;
            return a;
        }

        //Operator *
        public static BigFraction operator *(BigFraction a, BigFraction b)
        {
            a.Numerator = a.Numerator * b.Numerator;
            a.Denominator = a.Denominator * b.Denominator;
            return a;
        }

        //Operator /
        public static BigFraction operator /(BigFraction a, BigFraction b)
        {
            a.Numerator = a.Numerator * b.Denominator;
            a.Denominator = a.Denominator * b.Numerator;
            return a;
        }

        //Override Equals
        public override bool Equals(object obj)
        {
            if (obj == null) { return false; } 

            BigFraction comparebigfrac = (BigFraction)obj;
            if(Numerator == 0 && comparebigfrac.Numerator == 0) { return true; }    //If both values are zero

            return Numerator*comparebigfrac.Denominator == comparebigfrac.Numerator*Denominator;
        }

        //Override GetHashCode
        public override int GetHashCode()
        {
            return Numerator.GetHashCode() / Denominator.GetHashCode();
        }

        //Override ToString
        public override string ToString()
        {
            return Numerator.ToString() + "/" + Denominator.ToString();
        }

        //MISC

        public void Simplify()
        {
            BigInteger quotient = Numerator / Denominator;  //Separate quotient from the number for faster calculation
            BigInteger remainder = Numerator % Denominator;
            BigInteger gcd = BigInteger.GreatestCommonDivisor(remainder, Denominator);
            remainder = remainder / gcd;

            Denominator = Denominator / gcd;
            Numerator = (quotient * Denominator) + remainder;
        }

        //NOTE: ALWAYS use this method when converting from BigFraction to BigInteger.
        public BigInteger ToBigInteger()
        {
            return Numerator/Denominator;
        }

        //Conversion from double to fraction
        //Accuracy is used to convert recurring decimals into fractions (eg. 0.166667 -> 1/6)
        public static BigFraction FromDouble(double value, double accuracy)
        {
            if (accuracy <= 0.0 || accuracy >= 1.0)
            {
                throw new ArgumentOutOfRangeException("accuracy", "Must be > 0 and < 1.");
            }

            var sign = Math.Sign(value);

            if (sign == -1)
            {
                value = Math.Abs(value);
            }

            // Accuracy is the maximum relative error; convert to absolute maxError
            double maxError = sign == 0 ? accuracy : value * accuracy;

            var n = new BigInteger(value);
            value -= Math.Floor(value);

            if (value < maxError)
            {
                return new BigFraction(sign * n, BigInteger.One);
            }

            if (1 - maxError < value)
            {
                return new BigFraction(sign * (n + 1), BigInteger.One);
            }

            // The lower fraction is 0/1
            int lower_n = 0;
            int lower_d = 1;

            // The upper fraction is 1/1
            int upper_n = 1;
            int upper_d = 1;

            while (true)
            {
                // The middle fraction is (lower_n + upper_n) / (lower_d + upper_d)
                int middle_n = lower_n + upper_n;
                int middle_d = lower_d + upper_d;

                if (middle_d * (value + maxError) < middle_n)
                {
                    // real + error < middle : middle is our new upper
                    upper_n = middle_n;
                    upper_d = middle_d;
                }
                else if (middle_n < (value - maxError) * middle_d)
                {
                    // middle < real - error : middle is our new lower
                    lower_n = middle_n;
                    lower_d = middle_d;
                }
                else
                {
                    // Middle is our best fraction
                    return new BigFraction((n * middle_d + middle_n) * sign, middle_d);
                }
            }
        }
    }
}
