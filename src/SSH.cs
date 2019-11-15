using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.IO;
namespace SSHClientSharp
{
    class SSH
    {
        const string client_id = "SSH-2.0-AeroSSHSharp_0.0001";

        TcpClient tcp;
        string host;
        int port;
        string server_id = "";
        bool isMacOn = false;
        HMACSHA1 mac = new HMACSHA1();
        NetworkStream stream;
        public SSH(string host, int port = 22)
        {
            this.host = host;
            this.port = port;
        }
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
                            KexPacket a = new KexPacket(p);
                            KexPacket b = new KexPacket();
                            WritePacket(b);
                            //应该检查一下是否有相符的
                            KexDHInit dhi = new KexDHInit();
                            WritePacket(dhi);
                            break;
                        case SSH_MSG.KEXDH_REPLY:
                            KexDHReply dhr = new KexDHReply(p);
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
            uint padding_length = 8 - ((packet_length + 5) % 8);
            if (padding_length < 4) padding_length += 8;
            packet_length += padding_length + 1;
            List<byte> r = new List<byte>();
            r.AddRange(Util.UInt32Bytes(packet_length));
            r.Add((byte)padding_length);
            r.AddRange(payload);
            byte[] padding = new byte[padding_length];
            Util.RandomPadding(ref padding);
            r.AddRange(padding);
            //to-do mac;
            if (isMacOn)
            {
               // mac.Key
                //mac.ComputeHash();
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


