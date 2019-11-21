using System;
using System.Security.Cryptography;

namespace SSHClientSharp
{

    public class Aes128Ctr
    {
        Aes128CounterMode aes128ctr;
        ICryptoTransform encryptor;
        ICryptoTransform decryptor;

        public Aes128Ctr(byte[] key, byte[] counter)
        {
            aes128ctr = new Aes128CounterMode(counter);
            encryptor = aes128ctr.CreateEncryptor(key,null);
            decryptor = aes128ctr.CreateDecryptor(key,null);
        }
        public byte[] Encrypt(byte[] data)
        {
            byte[] en = new byte[data.Length];
            encryptor.TransformBlock(data,0,data.Length,en,0);
            return en;
        }
        

    }

    public class Aes128Ctr___________
    {
        Aes aes = Aes.Create();
        SimpleUInt128 ctr;
        ICryptoTransform encryptor;
        ICryptoTransform decryptor;
        public Aes128Ctr___________(byte[] key, byte[] counter)
        {
            if (key.Length != 128 / 8) throw new Exception("key should be 128bit");
            aes.Key = key;
            aes.Mode = CipherMode.ECB;
            ctr = new SimpleUInt128(counter);

            encryptor = aes.CreateEncryptor();
            decryptor = aes.CreateDecryptor();
        }
        public byte[] Encrypt(byte[] data)
        {
            int pos = 0;
            byte[] en = new byte[data.Length];
            for (; pos < data.Length; pos += aes.BlockSize / 8)
                EncryptBlock(data, en, pos);
            return en;
        }
        void EncryptBlock(byte[] src, byte[] dst, int pos)
        {
            encryptor.TransformBlock(ctr.ToBytes(), 0, aes.BlockSize / 8, dst, pos);
            for (int i = 0; i < aes.BlockSize / 8; i++)
            {
                dst[pos + i] = (byte)(dst[pos + i] ^ src[pos + i]);
            }
            ctr++;
        }
        public byte[] Decrypt(byte[] data)
        {
            int pos = 0;
            byte[] en = new byte[data.Length];
            for (; pos < data.Length; pos += aes.BlockSize / 8)
                DecryptBlock(data, en, pos);
            return en;

        }

        void DecryptBlock(byte[] src, byte[] dst, int pos)
        {
            decryptor.TransformBlock(ctr.ToBytes(), 0, aes.BlockSize / 8, dst, pos);
            for (int i = 0; i < aes.BlockSize / 8; i++)
            {
                dst[pos + i] = (byte)(dst[pos + i] ^ src[pos + i]);
            }
            ctr++;
        }
    }

    public struct SimpleUInt128
    {
        UInt64 H, L;
        bool isZero()
        {
            if (H == 0 && L == 0) return true;
            return false;
        }
        public SimpleUInt128(byte[] b)//Big ed
        {
            H = Util.GetUInt64(b, 0);
            L = Util.GetUInt64(b, 8);
        }
        public byte[] ToBytes()
        {
            byte[] r = new byte[16];
            Util.SetUInt64(ref r, H, 0);
            Util.SetUInt64(ref r, L, 8);
            return r;
        }
        public static SimpleUInt128 operator ++(SimpleUInt128 a)
        {
            a = a + 1;
            return a;
        }
        public static SimpleUInt128 operator +(SimpleUInt128 a, UInt64 b)
        {
            SimpleUInt128 c;
            c.L = a.L + b;
            c.H = a.H;
            if (c.L < a.L && a.L < b) c.H++;
            return c;
        }
    }


}