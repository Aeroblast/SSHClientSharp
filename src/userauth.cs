using System;



namespace SSHClientSharp
{
public class ServiceReqest:Packet
{
    string service_name;
    public ServiceReqest(string service_name)
    {
        this.service_name=service_name;
    }
    override public byte[] ToBytes()
    {
        byte[]a=Util.SSHStringBytes(service_name);
        byte[]r=new byte[a.Length+1];
        r[0]=(byte)SSH_MSG.SERVICE_REQUEST;
        a.CopyTo(r,1);
        return r;
    }
}

}