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




/*
        static void TestMPInt()
        {
            System.Numerics.BigInteger a;
            System.Numerics.BigInteger.TryParse("00deadbeef",System.Globalization.NumberStyles.AllowHexSpecifier,null,out a);
            byte[] b=Util.MPInt(a);
        }
*/
    }
}
