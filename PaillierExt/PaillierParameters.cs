using System;

namespace PaillierExt
{
    [Serializable]
    public struct PaillierParameters
    {
        public byte[] N;
        public byte[] G;
        public byte[] Lambda;
        public byte[] Miu;
    }
}
