using System;

namespace PaillierExt
{
        [Serializable] 
        public struct PaillierParameters
        {
            public byte[] N;
            public byte[] G;

            public PaillierPaddingMode Padding;
            [NonSerialized] 
            public byte[] Lambda;
            [NonSerialized]
            public byte[] Miu;
        }
}
