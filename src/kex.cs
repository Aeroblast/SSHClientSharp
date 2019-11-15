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
            payload.AddRange(Util.MPIntBytes(e));
            return payload.ToArray();
        }
    }
    
    public class KexDHReply
    {
        public KexDHReply(byte[] payload)
        {
            
            int pos=1;
            UInt32 hostkeylength=Util.GetUInt32(payload,pos);
            pos+=4;
            string keytype=Util.GetSSHString(payload,ref pos);
            BigInteger RSA_public_exponet=Util.GetMPInt(payload,ref pos);
            BigInteger RSA_modulus=Util.GetMPInt(payload,ref pos);
            BigInteger DH_server_f=Util.GetMPInt(payload,ref pos);
            BigInteger H= Util.GetMPInt(payload,ref pos);

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