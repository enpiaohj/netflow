using System.Net;
using System.Net.Sockets;
using NetFlow.Application;

namespace NetFlow.Desktop.Services;

/// <summary>
/// 当前选择的测试源网卡（顶栏下拉框设置，各测试页读取）。
/// null = 自动，由系统按路由选择；选定网卡则各探针按目标协议族绑定该网卡的地址。
/// </summary>
public static class SourceSelection
{
    /// <summary>已选网卡名；null = 自动。</summary>
    public static string? SelectedAdapterName { get; set; }

    /// <summary>
    /// 解析本次应绑定的源地址。自动时返回 (null, null)；
    /// 所选网卡已不可用或没有与目标同协议族的地址时返回错误文本（不静默回退，避免误以为走了所选网卡）。
    /// </summary>
    public static (IPAddress? Source, string? Error) Resolve(AddressFamily family)
    {
        if (SelectedAdapterName is not { } name) return (null, null);

        // 每次使用时重新读取，避免 DHCP 变更/网卡断开后仍用旧地址
        var current = SourceAdapterCatalog.List().FirstOrDefault(o => o.Name == name);
        if (current is null)
            return (null, $"所选源网卡“{name}”已不在线或没有可用地址，请在顶栏重新选择源网卡");

        var source = current.PickFor(family);
        if (source is null)
        {
            var kind = family == AddressFamily.InterNetworkV6 ? "IPv6" : "IPv4";
            return (null, $"所选源网卡“{name}”没有可用的 {kind} 地址，无法访问该目标；请改选其它网卡或“自动”");
        }
        return (source, null);
    }
}
