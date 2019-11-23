using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.IO;
namespace SSHClientSharp
{
    public class SSH
    {
        public string client_id = "SSH-2.0-AeroSSHSharp_0.0001";
        public string server_id = "";
        string host;
        TcpClient tcp;

        int port;

        bool isEncryptOn = false;
        HMACSHA1 mac_alg_cs;
        HMACSHA1 mac_alg_sc;
        Aes128Ctr en_alg_cs;
        Aes128Ctr en_alg_sc;
        NetworkStream stream;
        public SSH(string host, int port = 22)
        {
            this.host = host;
            this.port = port;
        }
        KexDHInit dhi;
        public byte[] kexinit_s_payload;
        KexDHReply dhr;
        public KexInit kexinit_s,kexinit_c;
        public void Connect()
        {
            tcp = new TcpClient(host, port);
            stream = tcp.GetStream();

            //协议版本交换
            while (true)
            {
                string s = ReadLine(255);
                if (s.StartsWith("SSH-"))
                {
                    server_id = s;
                    break;
                }
            }

            WriteLine(client_id);

            while (true)
            {
                byte[] p = ReadPacket();
                if (p == null) continue;

                if (Enum.IsDefined(typeof(SSH_MSG), p[0]))
                {
                    Log.log("[Info]Get  packet:type " + p[0] + " SSH_MSG_" + ((SSH_MSG)p[0]).ToString());
                    switch ((SSH_MSG)p[0])
                    {
                        case SSH_MSG.KEXINIT:
                            kexinit_s = new KexInit(p);
                            kexinit_s_payload=p;
                            kexinit_c = new KexInit();
                            WritePacket(kexinit_c);
                            //应该检查一下是否有相符的
                            dhi = new KexDHInit();
                            WritePacket(dhi);
                            break;
                        case SSH_MSG.KEXDH_REPLY:
                            dhr = new KexDHReply(p);
                            Keys kex=new Keys(dhi,dhr,this);
                            //CTR模式密钥 https://tools.ietf.org/html/rfc4344#section-4
                            mac_alg_cs=new HMACSHA1();
                            mac_alg_sc=new HMACSHA1();
                            mac_alg_cs.Key=kex.in_key_cs;
                            mac_alg_sc.Key=kex.in_key_sc;
                            en_alg_cs=new Aes128Ctr(kex.en_key_cs,kex.IV_cs);
                            en_alg_sc=new Aes128Ctr(kex.en_key_sc,kex.IV_sc);
                            isEncryptOn=true;
                            WritePacket(new NewKeys());
                            WritePacket(new ServiceReqest("ssh-userauth"));
                            break;
                    }
                }
                else
                {
                    throw new SSHException();
                }
            }


        }
        void WriteLine(string s)
        {
            byte[] b = Util.text_encoder.GetBytes(s + "\r\n");
            stream.Write(b, 0, b.Length);
        }
        string ReadLine(int max)
        {
            List<byte> buf = new List<byte>();
            byte b;
            for (int i = 0; i < max; i++)
            {
                b = ReadByte();
                char c = (char)b;
                if (c == '\r') break;
                buf.Add(b);
            }
            b = ReadByte();
            if ((char)b != '\n') throw new SSHException();
            return Util.text_encoder.GetString(buf.ToArray());
        }
        byte[] ReadPacket()
        {
            byte[] t = new byte[4];
            t[3] = ReadByte();
            t[2] = ReadByte();
            t[1] = ReadByte();
            t[0] = ReadByte();
            UInt32 packet_length = BitConverter.ToUInt32(t);
            if (packet_length == 0) return null;
            byte padding_length = ReadByte();
            UInt32 i = 0;
            byte[] payload = new byte[packet_length - padding_length - 1];
            for (; i < packet_length - padding_length - 1; i++)
            {
                payload[i] = ReadByte();
            }
            for (; i < packet_length - 1; i++)
            {
                ReadByte();
            }
            //to-do:mac
            return payload;
        }
        UInt32 packet_count_sent = 0;
        void WritePacket(Packet p)
        {
            byte[] payload = p.ToBytes();
            Log.log("[Info]Send packet:type " + payload[0] + " SSH_MSG_" + ((SSH_MSG)payload[0]).ToString());
            UInt32 packet_length = (UInt32)payload.Length;
            uint padding_length = 16 - ((packet_length + 5) % 16);
            if (padding_length < 4) padding_length += 16;
            packet_length += padding_length + 1;
            List<byte> r = new List<byte>();
            r.AddRange(Util.UInt32Bytes(packet_length));
            r.Add((byte)padding_length);
            r.AddRange(payload);
            byte[] padding = new byte[padding_length];
            Util.RandomPadding(ref padding);
            r.AddRange(padding);
            
            if (isEncryptOn)
            {
                byte[] raw_packet=r.ToArray();
                r.Clear();
                r.AddRange(en_alg_cs.Encrypt(raw_packet));                
                byte[] mac=mac_alg_cs.ComputeHash(raw_packet);
                r.AddRange(mac);
            }
            stream.Write(r.ToArray());
            packet_count_sent++;
        }
        //FileStream fileStream=new FileStream("debug.bin",FileMode.Create);
        byte ReadByte()
        {
            int t = stream.ReadByte();
            if (t < 0) throw new TcpEndException();
            //fileStream.WriteByte((byte)t);
            //fileStream.Flush();
            return (byte)t;
        }

    }
    public abstract class Packet
    {
        public abstract byte[] ToBytes();
    }

    public class SSHException : Exception
    {

    }
    public class TcpEndException : SSHException
    {

    }
}


