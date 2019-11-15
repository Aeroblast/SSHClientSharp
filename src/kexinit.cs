using System;
using System.Collections.Generic;

namespace SSHClientSharp
{

    //SSH_MSG.KEXINIT
    public class KexPacket:Packet
    {
        byte[] cookie=new byte[16];
        string[] kex_algorithms;//密钥交换算法
        string[] server_host_key_algorithms;
        string[] encryption_algorithms_client_to_server;//可接受对称加密器
        string[] encryption_algorithms_server_to_client;
        string[] mac_algorithms_client_to_server;
        string[] mac_algorithms_server_to_client;
        string[] compression_algorithms_client_to_server;
        string[] compression_algorithms_server_to_client;
        string[] languages_client_to_server;
        string[] languages_server_to_client;
        byte first_kex_packet_follows;
        UInt32 reserve;
        public KexPacket(byte[] data)
        {
            UInt32 pos = 1;
            for(uint i=0;i<16;i++)cookie[i]=data[pos+i];
            pos += 16;//cookie
            kex_algorithms = Util.GetNameList(data, ref pos);
            server_host_key_algorithms = Util.GetNameList(data, ref pos);
            encryption_algorithms_client_to_server = Util.GetNameList(data, ref pos);
            encryption_algorithms_server_to_client = Util.GetNameList(data, ref pos);
            mac_algorithms_client_to_server = Util.GetNameList(data, ref pos);
            mac_algorithms_server_to_client = Util.GetNameList(data, ref pos);
            compression_algorithms_client_to_server = Util.GetNameList(data, ref pos);
            compression_algorithms_server_to_client = Util.GetNameList(data, ref pos);
            languages_client_to_server = Util.GetNameList(data, ref pos);
            languages_server_to_client = Util.GetNameList(data, ref pos);
            first_kex_packet_follows = data[pos]; pos++;
            reserve=Util.GetUInt32(data,pos);
        }
        public KexPacket()
        {
            kex_algorithms=new string[]{"diffie-hellman-group14-sha1"};//备选diffie-hellman-group-exchange-sha256 RFC4419
            server_host_key_algorithms=new string[]{"ssh-rsa"};
            encryption_algorithms_client_to_server=new string[]{"aes128-ctr"};//标准是cbc
            encryption_algorithms_server_to_client=new string[]{"aes128-ctr"};
            mac_algorithms_client_to_server=new string[]{"hmac-sha1"};
            mac_algorithms_server_to_client=new string[]{"hmac-sha1"};
            compression_algorithms_client_to_server=new string[]{"none"};
            compression_algorithms_server_to_client=new string[]{"none"};
            languages_client_to_server=new string[0];
            languages_server_to_client=new string[0];
            first_kex_packet_follows=0;
            reserve=0;
        }
        override public byte[] ToBytes()
        {
            List<byte> r=new List<byte>();
            r.Add((byte)SSH_MSG.KEXINIT);
            r.AddRange(cookie);
            r.AddRange(Util.NameListBytes(kex_algorithms));
            r.AddRange(Util.NameListBytes(server_host_key_algorithms));
            r.AddRange(Util.NameListBytes(encryption_algorithms_client_to_server));
            r.AddRange(Util.NameListBytes(encryption_algorithms_server_to_client));
            r.AddRange(Util.NameListBytes(mac_algorithms_client_to_server));
            r.AddRange(Util.NameListBytes(mac_algorithms_server_to_client));
            r.AddRange(Util.NameListBytes(compression_algorithms_client_to_server));
            r.AddRange(Util.NameListBytes(compression_algorithms_server_to_client));
            r.AddRange(Util.NameListBytes(languages_client_to_server));
            r.AddRange(Util.NameListBytes(languages_server_to_client));
            r.Add(first_kex_packet_follows);
            r.AddRange(Util.UInt32Bytes(reserve));
            return r.ToArray();
        }

    }
}