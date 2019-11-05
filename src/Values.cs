namespace SSHClientSharp
{
    public enum SSH_MSG : byte
    {
        DISCONNET = 1,
        IGNORE = 2,
        UNIMPLEMENTED = 3,
        DEBUG = 4,
        SERVICE_REQUEST = 5,
        SERVICE_ACCEPT = 6,
        KEXINIT = 20,
        NEWKEYS = 21,
        GLOBAL_REQUEST = 80,
        REQUEST_SUCCESS = 81,
        REQUEST_FAILURE = 82,
        CHANNEL_OPEN = 90,
        CHANNEL_OPEN_CONFIRMATION = 91,
        CHANNEL_OPEN_FAILURE = 92,
        CHANNEL_WINDOW_ADJUST = 93,
        CHANNEL_DATA = 94,
        CHANNEL_EXTENDED_DATA = 95,
        CHANNEL_EOF = 96,
        CHANNEL_CLOSE = 97,
        CHANNEL_REQUEST = 98,
        CHANNEL_SUCCESS = 99,
        CHANNEL_FAILURE = 100
    }
}