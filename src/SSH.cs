using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
namespace SSHClientSharp
{
    class SSH
    {
        const string client_id = "SSH-2.0-AeroSSHSharp_0.0001";

        TcpClient tcp;
        string host;
        int port;
        string server_id = "";
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
                    switch ((SSH_MSG)p[0])
                    {
                        case SSH_MSG.KEXINIT:
                            KexPacket a = new KexPacket(p);
                            KexPacket b = new KexPacket();
                            WritePacket(b.ToBytes());
                            //WritePacket(new byte[]{(byte)SSH_MSG.NEWKEYS});
                            break;
                    }
                else
                {
                    throw new SSHException();
                }
            }


        }
        void WriteLine(string s)
        {
            byte[] b = Util.text_encoder.GetBytes(s);
            stream.Write(b, 0, b.Length);
            stream.WriteByte((byte)'\r');
            stream.WriteByte((byte)'\n');
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
            for (; i < packet_length; i++)
            {

            }
            //to-do:mac
            return payload;
        }
        void WritePacket(byte[] payload)
        {
            UInt32 packet_length = (UInt32)payload.Length;
            uint padding_length = 8 - ((packet_length + 5) % 8);
            if (padding_length < 4) padding_length += 8;
            packet_length += padding_length + 1;
            List<byte> r = new List<byte>();
            r.AddRange(Util.UInt32Bytes(packet_length));
            r.Add((byte)padding_length);
            r.AddRange(payload);
            byte[] padding = new byte[padding_length];
            r.AddRange(padding);
            //to-do mac;
            stream.Write(r.ToArray());
        }
        byte ReadByte()
        {
            int t = stream.ReadByte();
            if (t < 0) throw new TcpEndException();
            return (byte)t;
        }

    }
    abstract class PacketHandler
    {

    }

    public class SSHException : Exception
    {

    }
    public class TcpEndException : SSHException
    {

    }
}


