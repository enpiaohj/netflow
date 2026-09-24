using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetFlow.Application;

/// <summary>可选作为测试源的网卡及其可用于绑定的地址（多网卡/VPN 环境下由用户选择出包网卡）。</summary>
public sealed record SourceAdapterOption(string Name, IReadOnlyList<IPAddress> Addresses)
{
    /// <summary>下拉框显示：网卡名 + 首个 IPv4（无 IPv4 时用首个地址）。</summary>
    public string Display
    {
        get
        {
            var shown = Addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                ?? Addresses.FirstOrDefault();
            return shown is null ? Name : $"{Name}（{shown}）";
        }
    }

    /// <summary>取指定协议族的可绑定地址；该网卡没有此协议族的可用地址则返回 null。</summary>
    public IPAddress? PickFor(AddressFamily family) =>
        Addresses.FirstOrDefault(a => a.AddressFamily == family);
}

/// <summary>枚举可作为测试源的网卡。仅纳入在线、非回环、且有可用单播地址的网卡。</summary>
public static class SourceAdapterCatalog
{
    public static IReadOnlyList<SourceAdapterOption> List()
    {
        var result = new List<SourceAdapterOption>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            if (nic.OperationalStatus != OperationalStatus.Up) continue;

            var addresses = nic.GetIPProperties().UnicastAddresses.Select(a => a.Address);
            var option = Create(nic.Name, addresses);
            if (option is not null) result.Add(option);
        }
        return result;
    }

    /// <summary>由网卡名与其地址构造选项（纯函数，便于测试）；没有可用地址返回 null。</summary>
    public static SourceAdapterOption? Create(string name, IEnumerable<IPAddress> addresses)
    {
        var usable = addresses.Where(IsUsableSource).ToList();
        return usable.Count == 0 ? null : new SourceAdapterOption(name, usable);
    }

    /// <summary>排除回环、IPv4 自动私有地址（169.254/16，无 DHCP 时的自分配）与 IPv6 链路本地地址。</summary>
    public static bool IsUsableSource(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)) return false;
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return !address.IsIPv6LinkLocal;
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = address.GetAddressBytes();
            return !(b[0] == 169 && b[1] == 254);
        }
        return false;
    }
}
