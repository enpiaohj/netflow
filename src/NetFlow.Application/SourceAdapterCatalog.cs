using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetFlow.Application;

/// <summary>网卡大类：用于选择默认源网卡（有线优先于无线，其余如 VPN/隧道最后）。</summary>
public enum SourceAdapterKind
{
    Ethernet,
    Wireless,
    Other,
}

/// <summary>可选作为测试源的网卡及其可用于绑定的地址（多网卡/VPN 环境下由用户选择出包网卡）。</summary>
public sealed record SourceAdapterOption(
    string Name,
    IReadOnlyList<IPAddress> Addresses,
    bool HasDefaultGateway = false,
    SourceAdapterKind Kind = SourceAdapterKind.Other)
{
    /// <summary>下拉框显示：网卡名 + 首个 IPv4（无 IPv4 时用首个地址）；带默认网关的网卡加注。</summary>
    public string Display
    {
        get
        {
            var shown = Addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                ?? Addresses.FirstOrDefault();
            var text = shown is null ? Name : $"{Name}（{shown}）";
            return HasDefaultGateway ? text + " · 默认网关" : text;
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

            var props = nic.GetIPProperties();
            var hasGateway = props.GatewayAddresses.Any(g =>
                !g.Address.Equals(IPAddress.Any) && !g.Address.Equals(IPAddress.IPv6Any));
            var option = Create(nic.Name, props.UnicastAddresses.Select(a => a.Address),
                hasGateway, KindOf(nic.NetworkInterfaceType));
            if (option is not null) result.Add(option);
        }
        return Order(result);
    }

    /// <summary>由网卡名与其地址构造选项（纯函数，便于测试）；没有可用地址返回 null。</summary>
    public static SourceAdapterOption? Create(
        string name, IEnumerable<IPAddress> addresses,
        bool hasDefaultGateway = false, SourceAdapterKind kind = SourceAdapterKind.Other)
    {
        var usable = addresses.Where(IsUsableSource).ToList();
        return usable.Count == 0 ? null : new SourceAdapterOption(name, usable, hasDefaultGateway, kind);
    }

    /// <summary>排序：带默认网关优先，其次有线 → 无线 → 其他；同级保持系统枚举顺序（稳定排序）。</summary>
    public static IReadOnlyList<SourceAdapterOption> Order(IEnumerable<SourceAdapterOption> options) =>
        [.. options.OrderByDescending(o => o.HasDefaultGateway).ThenBy(o => (int)o.Kind)];

    /// <summary>
    /// 默认源网卡：带默认网关的以太网卡；没有则依次退到带网关的无线/其他网卡，
    /// 再没有则取第一个可用网卡；无任何可用网卡返回 null。
    /// </summary>
    public static SourceAdapterOption? PickDefault(IEnumerable<SourceAdapterOption> options) =>
        Order(options).FirstOrDefault();

    public static SourceAdapterKind KindOf(NetworkInterfaceType type) => type switch
    {
        NetworkInterfaceType.Ethernet or NetworkInterfaceType.Ethernet3Megabit
            or NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.FastEthernetFx
            or NetworkInterfaceType.GigabitEthernet => SourceAdapterKind.Ethernet,
        NetworkInterfaceType.Wireless80211 => SourceAdapterKind.Wireless,
        _ => SourceAdapterKind.Other,
    };

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
