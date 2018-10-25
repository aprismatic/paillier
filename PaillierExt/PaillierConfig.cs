/**
 * Configuration file for various parameters
 **/
namespace PaillierExt
{
    public struct PaillierConfig
    {
        //Affects size of plain text, value has to be powers of 2
        public static readonly int size = 256;

        //Number of decimal places allowed in plain text
        public static readonly int exponent = 2;
    }
}
