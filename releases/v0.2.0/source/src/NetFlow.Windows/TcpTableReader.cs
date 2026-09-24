using System.Runtime.InteropServices;
using System.Text;

namespace NetFlow.Windows;

/// <summary>TCP/UDP 监听与连接表（含 PID 与进程名）。</summary>
public sealed record SocketEndpointInfo
{
    public required string Protocol { get; init; }
    public required string LocalAddress { get; init; }
    public required int LocalPort { get; init; }
    public string? RemoteAddress { get; init; }
    public int? RemotePort { get; init; }
    public required string State { get; init; }
    public required int Pid { get; init; }
    public required string ProcessName { get; init; }
    public required string ProcessPath { get; init; }
}

/// <summary>
/// 使用 GetExtendedTcpTable/GetExtendedUdpTable（iphlpapi）直接读取端口表，
/// 不依赖外部命令。监听状态仅表示本机应用接受连接，不代表远端可访问。
/// </summary>
public static class TcpTableReader
{
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;
    private const long AfInet = 2;
    private const long AfInet6 = 23;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable, ref uint dwSize, bool bOrder, long ulAf, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable, ref uint dwSize, bool bOrder, long ulAf, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort; // 高 16 位，网络序
        public uint RemoteAddr;
        public uint RemotePort;
        public int OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public uint LocalPort;
        public int OwningPid;
    }

    public static IReadOnlyList<SocketEndpointInfo> GetTcpEndpoints(bool requireAdmin = false)
    {
        long af = AfInet;
        uint size = 0;
        _ = GetExtendedTcpTable(IntPtr.Zero, ref size, true, af, TcpTableOwnerPidAll, 0);
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            var rc = GetExtendedTcpTable(buffer, ref size, true, af, TcpTableOwnerPidAll, 0);
            if (rc != 0)
                throw new InvalidOperationException($"GetExtendedTcpTable 失败：{rc}");

            int count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var list = new List<SocketEndpointInfo>(count);
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(
                    buffer + sizeof(int) + i * rowSize);
                list.Add(new SocketEndpointInfo
                {
                    Protocol = "TCP",
                    LocalAddress = FormatIpv4(row.LocalAddr),
                    LocalPort = (int)((row.LocalPort >> 8) | ((row.LocalPort & 0xFF) << 8)),
                    RemoteAddress = FormatIpv4(row.RemoteAddr),
                    RemotePort = (int)((row.RemotePort >> 8) | ((row.RemotePort & 0xFF) << 8)),
                    State = TcpStateText(row.State),
                    Pid = row.OwningPid,
                    ProcessName = ProcessNameOf(row.OwningPid),
                    ProcessPath = ProcessPathOf(row.OwningPid),
                });
            }
            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static IReadOnlyList<SocketEndpointInfo> GetUdpEndpoints()
    {
        long af = AfInet;
        uint size = 0;
        _ = GetExtendedUdpTable(IntPtr.Zero, ref size, true, af, UdpTableOwnerPid, 0);
        var buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            var rc = GetExtendedUdpTable(buffer, ref size, true, af, UdpTableOwnerPid, 0);
            if (rc != 0)
                throw new InvalidOperationException($"GetExtendedUdpTable 失败：{rc}");

            int count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
            var list = new List<SocketEndpointInfo>(count);
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(
                    buffer + sizeof(int) + i * rowSize);
                list.Add(new SocketEndpointInfo
                {
                    Protocol = "UDP",
                    LocalAddress = FormatIpv4(row.LocalAddr),
                    LocalPort = (int)((row.LocalPort >> 8) | ((row.LocalPort & 0xFF) << 8)),
                    State = "-",
                    Pid = row.OwningPid,
                    ProcessName = ProcessNameOf(row.OwningPid),
                    ProcessPath = ProcessPathOf(row.OwningPid),
                });
            }
            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string FormatIpv4(uint addrBigEndian)
    {
        var b = BitConverter.GetBytes(addrBigEndian);
        return $"{b[0]}.{b[1]}.{b[2]}.{b[3]}";
    }

    private static string TcpStateText(uint state) => state switch
    {
        2 => "LISTENING",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        1 => "CLOSED",
        _ => $"STATE_{state}",
    };

    private static readonly Dictionary<int, string> ProcessNameCache = new();

    private static string ProcessNameOf(int pid)
    {
        if (pid == 0) return "System Idle";
        lock (ProcessNameCache)
        {
            if (ProcessNameCache.TryGetValue(pid, out var name)) return name;
        }
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            var n = p.ProcessName;
            lock (ProcessNameCache) ProcessNameCache[pid] = n;
            return n;
        }
        catch
        {
            return "（进程已退出或无权限）";
        }
    }

    private static string ProcessPathOf(int pid)
    {
        if (pid == 0) return string.Empty;
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return p.MainModule?.FileName ?? string.Empty;
        }
        catch
        {
            // MainModule 需要同位数/权限；权限不足时留空并如实标注
            return string.Empty;
        }
    }
}
