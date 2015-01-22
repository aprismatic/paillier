using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
