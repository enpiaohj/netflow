using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace NetFlow.Probes;

/// <summary>
/// 可指定源地址的 IPv4 ICMP 回显（iphlpapi.dll IcmpSendEcho2Ex）。
/// .NET 的 <see cref="Ping"/> 无法绑定源地址，多网卡环境下无法保证 Ping/路径探测从所选网卡发出。
/// 状态码与 <see cref="IPStatus"/> 数值一致，直接映射。
/// </summary>
internal static class IcmpEchoV4
{
    private const int IpFlagDontFragment = 0x02;
    private const int ErrIpReqTimedOut = 11010;

    [StructLayout(LayoutKind.Sequential)]
    private struct IpOptionInformation
    {
        public byte Ttl;
        public byte Tos;
        public byte Flags;
        public byte OptionsSize;
        public IntPtr OptionsData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IcmpEchoReply
    {
        public uint Address;
        public uint Status;
        public uint RoundTripTime;
        public ushort DataSize;
        public ushort Reserved;
        public IntPtr Data;
        public IpOptionInformation Options;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern IntPtr IcmpCreateFile();

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern bool IcmpCloseHandle(IntPtr handle);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint IcmpSendEcho2Ex(
        IntPtr icmpHandle, IntPtr evt, IntPtr apcRoutine, IntPtr apcContext,
        uint sourceAddress, uint destinationAddress,
        byte[] requestData, ushort requestSize,
        ref IpOptionInformation requestOptions,
        IntPtr replyBuffer, uint replySize, uint timeout);

    /// <summary>同步发送一次回显（阻塞至应答或超时，调用方应放到线程池）。系统级失败抛 <see cref="Win32Exception"/>。</summary>
    public static (IPStatus Status, IPAddress? From, long RttMs) Send(
        IPAddress source, IPAddress destination, int timeoutMs, byte ttl, byte[] payload)
    {
        var handle = IcmpCreateFile();
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        // 应答缓冲：ICMP_ECHO_REPLY + 载荷 + 8 字节 ICMP 错误信息 + IO_STATUS_BLOCK，留足余量
        var replySize = (uint)(Marshal.SizeOf<IcmpEchoReply>() + payload.Length + 8 + 16 + 64);
        var replyBuffer = Marshal.AllocHGlobal((int)replySize);
        try
        {
            var options = new IpOptionInformation { Ttl = ttl, Flags = IpFlagDontFragment };
            var replies = IcmpSendEcho2Ex(
                handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                ToUInt(source), ToUInt(destination),
                payload, (ushort)payload.Length, ref options,
                replyBuffer, replySize, (uint)timeoutMs);

            if (replies == 0)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == ErrIpReqTimedOut) return (IPStatus.TimedOut, null, 0);
                // 11000–11050 为 IP_STATUS 区间（如目标不可达），其余为系统级错误（如源地址不属于本机）
                if (error is >= 11000 and <= 11050) return ((IPStatus)error, null, 0);
                throw new Win32Exception(error);
            }

            var reply = Marshal.PtrToStructure<IcmpEchoReply>(replyBuffer);
            var from = new IPAddress(BitConverter.GetBytes(reply.Address));
            return ((IPStatus)reply.Status, from, reply.RoundTripTime);
        }
        finally
        {
            Marshal.FreeHGlobal(replyBuffer);
            IcmpCloseHandle(handle);
        }
    }

    private static uint ToUInt(IPAddress address) => BitConverter.ToUInt32(address.GetAddressBytes(), 0);
}
