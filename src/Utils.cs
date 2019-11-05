using System;
using System.Text;
namespace SSHClientSharp
{
    class Util
    {
        public static UTF8Encoding text_encoder = new UTF8Encoding();

        public static byte[] SubReverseArray(byte[] src, ulong start, ulong length)
        {
            byte[] r = new byte[length];
            for (ulong i = 0; i < length; i++) { r[i] = src[start+length - i-1]; }
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
        public static string[] ReadNameList(byte[] src, ref UInt32 pos)
        {
            UInt32 length = GetUInt32(src, pos);
            pos += 4;
            string s=text_encoder.GetString(src,(int)pos,(int)length);
            pos+=length;
            return s.Split(',');
        }
    }
}
