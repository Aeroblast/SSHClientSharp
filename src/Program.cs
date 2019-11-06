using System;
using System.Net.Sockets;
namespace SSHClientSharp
{
    class Program
    {
        static void Main(string[] args)
        {
            SSH ssh=new SSH("127.0.0.1",22);
            ssh.Connect();
        }
    }
}
