using System;
namespace SSHClientSharp
{

    //SSH_MSG.KEXINIT
    public class KexPacket
    {
        byte[] cookie=new byte[16];
        string[] key_algorithms;
        string[] server_host_key_algorithms;
        string[] encryption_algorithms_client_to_server;
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
            key_algorithms = Util.GetNameList(data, ref pos);
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
    }
}