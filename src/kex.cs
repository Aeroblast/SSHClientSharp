using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
namespace SSHClientSharp
{
    public class KexDHInit : Packet
    {
        public BigInteger g, x, q;
        public BigInteger e;
        public KexDHInit()
        {
            Random random = new Random();
            BigInteger.TryParse(Const.group14q, System.Globalization.NumberStyles.AllowHexSpecifier, null, out q);
            g = 2;//group14
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
        //Kex Dh Reply
        public byte[] hostkey;
        public BigInteger DH_server_f;
        public byte[] H;


        //ssh-rsa
        public string keytype;
        public byte[] RSA_public_exponet;
        public byte[] RSA_modulus;
        public KexDHReply(byte[] payload)
        {

            int pos = 1;
            hostkey = Util.GetSSHRawString(payload, ref pos);
            DH_server_f = Util.GetMPInt(payload, ref pos);
            H = Util.GetSSHRawString(payload, ref pos);

            if (pos != payload.Length) throw new SSHException();

            int pos_rsa = 0;
            keytype = Util.GetSSHString(hostkey, ref pos_rsa);
            RSA_public_exponet = Util.GetSSHRawString(hostkey, ref pos_rsa);
            RSA_modulus = Util.GetSSHRawString(hostkey, ref pos_rsa);
            if (RSA_modulus.Length != 257) throw new SSHException();
            if (pos_rsa != hostkey.Length) throw new SSHException();

        }

    }
    //https://tools.ietf.org/html/rfc4253#section-7.2
    public class Keys
    {
        BigInteger _key;
        byte[] K;
        byte[] H;
        byte[] session_id;

        public byte[] IV_cs;
        public byte[] IV_sc;
        public byte[] en_key_cs;
        public byte[] en_key_sc;
        public byte[] in_key_cs;
        public byte[] in_key_sc;
        KexDHReply server;
        KexDHInit client;

        SSH context;
        public Keys(KexDHInit client, KexDHReply server, SSH context)
        {
            this.server = server;
            this.client = client;
            this.context = context;

            _key = BigInteger.ModPow(client.e, server.DH_server_f, client.q);
            K = Util.MPIntBytes(_key);
            TestExchangeHash();
            H = server.H;
            session_id = server.H;
            IV_cs = ComputeToLength((byte)'A', 128 / 8);
            IV_sc = ComputeToLength((byte)'B', 128 / 8);
            en_key_cs = ComputeToLength((byte)'C', 128 / 8);
            en_key_sc = ComputeToLength((byte)'D', 128 / 8);
            in_key_cs = ComputeToLength((byte)'E', 20);
            in_key_sc = ComputeToLength((byte)'F', 20);

        }
        SHA1 hash = SHA1.Create();
        byte[] ComputeToLength(byte x, int request_length)
        {
            byte[] r = new byte[request_length];
            byte[] t = ComputeHash(K, H, new byte[] { x }, session_id);
            if (t.Length > request_length)
            {
                for (int i = 0; i < r.Length; i++) r[i] = t[i];
            }
            else
            {
                List<byte> keys = new List<byte>();
                keys.AddRange(t);
                int perkeylength = keys.Count;
                while (request_length > keys.Count)
                {
                    keys.AddRange(ComputeHash(K, H, keys.ToArray(), null));
                }
                keys.CopyTo(0, r, 0, request_length);
            }

            return r;
        }
        byte[] ComputeHash(byte[] a, byte[] b, byte[] c, byte[] d)
        {
            List<byte> buf = new List<byte>();
            if (a != null) buf.AddRange(a);
            if (b != null) buf.AddRange(b);
            if (c != null) buf.AddRange(c);
            if (d != null) buf.AddRange(d);
            return hash.ComputeHash(buf.ToArray());
        }

        void TestExchangeHash()
        {
            /*
            From RFC 4253:
            The "ssh-rsa" key format has the following specific encoding:

                  string    "ssh-rsa"
                  mpint     e
                  mpint     n

            Here the 'e' and 'n' parameters form the signature key blob.

            Signing and verifying using this key format is performed according to
            the RSASSA-PKCS1-v1_5 scheme in [RFC3447] using the SHA-1 hash.

            The resulting signature is encoded as follows:

                  string    "ssh-rsa"
                  string    rsa_signature_blob
            */

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            var rsa_para = new RSAParameters();
            byte[] public_key_2048bit = new byte[256];
            for (int i = 0; i < 256; i++) public_key_2048bit[i] = server.RSA_modulus[i + 1];
            rsa_para.Exponent = server.RSA_public_exponet;
            rsa_para.Modulus = public_key_2048bit;
            rsa.ImportParameters(rsa_para);
            int pos = 0;
            string s = Util.GetSSHString(server.H, ref pos);//"ssh-rsa"
            byte[] a = Util.GetSSHRawString(server.H, ref pos);

            List<byte> H_src = new List<byte>();
            H_src.AddRange(Util.SSHStringBytes(context.client_id));
            H_src.AddRange(Util.SSHStringBytes(context.server_id));
            H_src.AddRange(context.kexinit_c.ToBytes());
            H_src.AddRange(context.kexinit_s.ToBytes());
            H_src.AddRange(server.hostkey);
            H_src.AddRange(Util.MPIntBytes(client.e));
            H_src.AddRange(Util.MPIntBytes(server.DH_server_f));
            H_src.AddRange(K);
            byte[] hash_local=hash.ComputeHash(H_src.ToArray());
            byte[] h = rsa.Encrypt(hash_local, false);//RSASSA-PKCS1-v1_5
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