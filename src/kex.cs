using System;
using System.Collections.Generic;
using System.Numerics;
namespace SSHClientSharp
{
    public class KexDHInit : Packet
    {
        public BigInteger g, x, q;
        BigInteger e;
        public KexDHInit()
        {
            Random random = new Random();
            BigInteger.TryParse(Const.group14q, System.Globalization.NumberStyles.AllowHexSpecifier, null, out q);
            g = 2;//group14
            x =
            e = BigInteger.ModPow(g, x, q);
            do
            {
                x = Util.RandomBigInteger(q.GetByteCount());

                e = BigInteger.ModPow(g, x, q);

            } while (e < 1 || e > ((q - 1)));

        }
        public override byte[] ToBytes()
        {
            List<byte> payload = new List<byte>();
            payload.Add((byte)SSH_MSG.KEXDH_INIT);
            payload.AddRange(Util.MPInt(e));
            return payload.ToArray();
        }
    }
    public class NewKeys : Packet
    {
        public override byte[] ToBytes()
        {
            return new byte[] { (byte)SSH_MSG.NEWKEYS };
        }
    }
}