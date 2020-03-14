namespace Aprismatic.PaillierExt
{
    public abstract class PaillierAbstractCipher
    {
        protected readonly int CiphertextBlocksize;
        protected PaillierKeyStruct KeyStruct;

        public PaillierAbstractCipher(PaillierKeyStruct keyStruct)
        {
            KeyStruct = keyStruct;
            CiphertextBlocksize = keyStruct.getCiphertextBlocksize();
        }
    }
}
