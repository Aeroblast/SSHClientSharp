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
                string s = GetLine(255);
                if (s.StartsWith("SSH-"))
                {
                    server_id = s;
                    break;
                }
            }

            SendLine(client_id);

            while (true)
            {
                byte[] p = GetPacket();
                if (Enum.IsDefined(typeof(SSH_MSG), p[0]))
                    switch ((SSH_MSG)p[0])
                    {
                        case SSH_MSG.KEXINIT:
                        KexPacket a=new KexPacket(p);
                            break;
                    }
                else
                {
                    throw new SSHException();
                }
            }


        }
        void SendLine(string s)
        {
            byte[] b = Util.text_encoder.GetBytes(s);
            stream.Write(b, 0, b.Length);
            stream.WriteByte((byte)'\r');
            stream.WriteByte((byte)'\n');
        }
        string GetLine(int max)
        {
            List<byte> buf = new List<byte>();
            byte b;
            for (int i = 0; i < max; i++)
            {
                b = GetByte();
                char c = (char)b;
                if (c == '\r') break;
                buf.Add(b);
            }
            b = GetByte();
            if ((char)b != '\n') throw new SSHException();
            return Util.text_encoder.GetString(buf.ToArray());
        }
        byte[] GetPacket()
        {
            byte[] t = new byte[4];
            t[3] = GetByte();
            t[2] = GetByte();
            t[1] = GetByte();
            t[0] = GetByte();
            UInt32 packet_length = BitConverter.ToUInt32(t);
            byte padding_length = GetByte();
            UInt32 i = 0;
            byte[] payload = new byte[packet_length - padding_length - 1];
            for (; i < packet_length - padding_length - 1; i++)
            {
                payload[i] = GetByte();
            }
            for (; i < packet_length; i++)
            {

            }
            return payload;
        }
        byte GetByte()
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


