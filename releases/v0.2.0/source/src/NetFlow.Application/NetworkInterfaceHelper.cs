using System.Net;
using System.Net.NetworkInformation;
using System.Security.Principal;

namespace NetFlow.Application;

/// <summary>本机环境快照辅助。</summary>
public static class NetworkInterfaceHelper
{
    /// <summary>优先网卡名：若指定源地址则取其网卡；否则取默认路由出口的第一块非回环网卡。</summary>
    public static string? GetPreferredAdapterName(IPAddress? sourceAddress)
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var ips = nic.GetIPProperties().UnicastAddresses;
            if (sourceAddress is not null &&
                ips.Any(a => a.Address.Equals(sourceAddress)))
                return nic.Name;
        }

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            if (nic.OperationalStatus == OperationalStatus.Up &&
                nic.GetIPProperties().GatewayAddresses.Count > 0)
                return nic.Name;
        }
        return null;
    }

    /// <summary>当前进程是否已提升管理员权限（非 Windows 返回 false）。</summary>
    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
