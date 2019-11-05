using System;
using System.Net.Sockets;
namespace SSHClientSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            SSH ssh=new SSH("192.168.1.103",22);
            ssh.Connect();
        }
    }
}
