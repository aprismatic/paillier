namespace PaillierExt
{
    public abstract class PaillierAbstractCipher
    {
        protected readonly int CiphertextBlocksize;
        protected PaillierKeyStruct KeyStruct;

        public PaillierAbstractCipher(PaillierKeyStruct p_key_struct)
        {
            KeyStruct = p_key_struct;
            CiphertextBlocksize = p_key_struct.getCiphertextBlocksize();
        }
    }
}
