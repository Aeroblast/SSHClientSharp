using System;
using System.Collections.Generic;
using System.Text;
using System.Numerics;
using System.Security.Cryptography;
namespace SSHClientSharp
{
    class Util
    {
        public static UTF8Encoding text_encoder = new UTF8Encoding();

        public static byte[] SubReverseArray(byte[] src, ulong start, ulong length)
        {
            byte[] r = new byte[length];
            for (ulong i = 0; i < length; i++) { r[i] = src[start + length - i - 1]; }
            return r;
        }
        public static UInt64 GetUInt64(byte[] src, ulong start)
        {
            byte[] t = SubReverseArray(src, start, 8);
            return BitConverter.ToUInt64(t);
        }
        //big edian handle:
        public static UInt32 GetUInt32(byte[] src, ulong start)
        {
            byte[] t = SubReverseArray(src, start, 4);
            return BitConverter.ToUInt32(t);
        }
        public static UInt16 GetUInt16(byte[] src, ulong start)
        {
            byte[] t = SubReverseArray(src, start, 2);

            return BitConverter.ToUInt16(t);
        }
        public static string[] GetNameList(byte[] src, ref UInt32 pos)
        {
            UInt32 length = GetUInt32(src, pos);
            pos += 4;
            string s = text_encoder.GetString(src, (int)pos, (int)length);
            pos += length;
            return s.Split(',');
        }
        public static void SetUInt32(ref byte[] target, UInt32 i, int pos)
        {
            byte[] c = BitConverter.GetBytes(i);
            for (int a = 0; a < 4; a++)
            {
                target[pos + a] = c[3 - a];
            }
        }
        public static byte[] UInt32Bytes(UInt32 i)
        {
            byte[] a = BitConverter.GetBytes(i);
            Array.Reverse(a);
            return a;
        }
        public static byte[] NameListBytes(string[] list)
        {
            string s = "";
            if (list == null || list.Length == 0)
            {
                return new byte[4];
            }
            foreach (var a in list)
            {
                s += a + ",";
            }
            byte[] b = text_encoder.GetBytes(s, 0, s.Length - 1);
            byte[] r = new byte[b.Length + 4];
            UInt32 l = (UInt32)b.Length;
            SetUInt32(ref r, l, 0);
            b.CopyTo(r, 4);
            return r;
        }
        public static byte[] MPInt(BigInteger n)
        {
            byte[] a=n.ToByteArray(false,true);
            UInt32 l= (UInt32)a.Length;
            List<byte> r=new List<byte>();
            r.AddRange(UInt32Bytes(l));
            r.AddRange(a);
            return r.ToArray();
        }
        static Random random=new Random();
        public static void RandomPadding(ref byte[] a)
        {
            random.NextBytes(a);
        }

        private static RNGCryptoServiceProvider randomizer = new RNGCryptoServiceProvider();
        public static BigInteger RandomBigInteger(int byteLength)
        {
            var bytesArray = new byte[byteLength];
            randomizer.GetBytes(bytesArray);
            bytesArray[bytesArray.Length - 1] = (byte)(bytesArray[bytesArray.Length - 1] & 0x7F);   //  Ensure not a negative value
            return new BigInteger(bytesArray);
        }
    }
}
