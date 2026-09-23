using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetFlow.Windows;

/// <summary>本机网卡画像（设计文档 4.1）。</summary>
public sealed record AdapterProfile
{
    public required string Name { get; init; }
    public required string Id { get; init; }
    public required string Description { get; init; }
    public required NetworkInterfaceType InterfaceType { get; init; }
    public required OperationalStatus Status { get; init; }
    public required bool IsLoopback { get; init; }
    public required string? MacAddress { get; init; }
    public required IReadOnlyList<string> Ipv4Addresses { get; init; }
    public required IReadOnlyList<string> Ipv4Prefixes { get; init; }
    public required IReadOnlyList<string> Ipv6Addresses { get; init; }
    public required IReadOnlyList<string> Gateways { get; init; }
    public required IReadOnlyList<string> DnsServers { get; init; }
    public required IReadOnlyList<string> DnsSuffixes { get; init; }
    public required long Speed { get; init; }
}

/// <summary>路由表项。</summary>
public sealed record RouteEntry
{
    public required string Destination { get; init; }
    public required string PrefixLength { get; init; }
    public required string NextHop { get; init; }
    public required string InterfaceAlias { get; init; }
    public required string RouteMetric { get; init; }
    public required string Protocol { get; init; }
}

/// <summary>针对目标的路由选择结果。</summary>
public sealed record RouteSelection
{
    public required string Target { get; init; }
    public string? SourceAddress { get; init; }
    public string? NextHop { get; init; }
    public string? Interface { get; init; }
    public string? Explanation { get; init; }
}

/// <summary>
/// 本机网络画像采集（设计文档 4.1）。
/// 系统配置读取优先 .NET 网络信息 API；路由表使用 PowerShell 官方模块（固定路径/参数数组）。
/// </summary>
public static class NetworkProfileCollector
{
    public static IReadOnlyList<AdapterProfile> CollectAdapters()
    {
        var result = new List<AdapterProfile>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            var ip = nic.GetIPProperties();
            var v4 = ip.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .ToList();
            var v6 = ip.UnicastAddresses.Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6)
                .ToList();

            result.Add(new AdapterProfile
            {
                Name = nic.Name,
                Id = nic.Id,
                Description = nic.Description,
                InterfaceType = nic.NetworkInterfaceType,
                Status = nic.OperationalStatus,
                IsLoopback = nic.NetworkInterfaceType == NetworkInterfaceType.Loopback,
                MacAddress = string.Join("-", nic.GetPhysicalAddress().GetAddressBytes()
                    .Select(b => b.ToString("X2"))),
                Ipv4Addresses = [.. v4.Select(a => a.Address.ToString())],
                Ipv4Prefixes = [.. v4.Select(a => $"{a.Address}/{a.PrefixLength}")],
                Ipv6Addresses = [.. v6.Select(a => $"{a.Address}/{a.PrefixLength}")],
                Gateways = [.. ip.GatewayAddresses.Select(g => g.Address.ToString())],
                DnsServers = [.. ip.DnsAddresses.Select(d => d.ToString())],
                DnsSuffixes = string.IsNullOrEmpty(ip.DnsSuffix)
                    ? []
                    : [ip.DnsSuffix],
                Speed = nic.Speed,
            });
        }
        return result;
    }

    /// <summary>系统代理状态（WinINET/HttpClient 默认代理）。</summary>
    public static string GetProxyStatus()
    {
        try
        {
            var proxy = System.Net.Http.HttpClient.DefaultProxy;
            var target = new Uri("https://example.com/");
            var via = proxy.GetProxy(target);
            return via is null ? "未配置系统代理（直连）" : $"系统代理：{via}";
        }
        catch (Exception ex)
        {
            return $"代理状态读取失败：{ex.Message}";
        }
    }

    /// <summary>路由表（IPv4）。经 PowerShell Get-NetRoute，逐项解析失败不静默。</summary>
    public static async Task<IReadOnlyList<RouteEntry>> CollectRoutesAsync(
        CancellationToken ct = default)
    {
        var script = """
            Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
              Sort-Object RouteMetric |
              Select-Object -First 100 @{n='Destination';e={$_.DestinationPrefix}},
                @{n='PrefixLength';e={$_.PrefixLength}},
                @{n='NextHop';e={$_.NextHop}},
                @{n='InterfaceAlias';e={$_.InterfaceAlias}},
                @{n='RouteMetric';e={$_.RouteMetric}},
                @{n='Protocol';e={$_.Protocol}} | ConvertTo-Json -Compress
            """;
        var result = await ProcessRunner.RunPowerShellAsync(script,
            TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"路由表查询失败（exit {result.ExitCode}）：{result.StandardError.Trim()}");
        }
        return ParseRouteJson(result.StandardOutput);
    }

    /// <summary>解析 Get-NetRoute 的 JSON（单条或多条）。public 以便离线单元测试。</summary>
    public static IReadOnlyList<RouteEntry> ParseRouteJson(string json)
    {
        var list = new List<RouteEntry>();
        if (string.IsNullOrWhiteSpace(json)) return list;
        var node = System.Text.Json.JsonDocument.Parse(json.Trim()).RootElement;
        if (node.ValueKind == System.Text.Json.JsonValueKind.Array)
        {
            foreach (var item in node.EnumerateArray())
                list.Add(ToRoute(item));
        }
        else
        {
            list.Add(ToRoute(node));
        }
        return list;
    }

    private static RouteEntry ToRoute(System.Text.Json.JsonElement e) =>
        new()
        {
            Destination = Str(e, "Destination"),
            PrefixLength = Str(e, "PrefixLength"),
            NextHop = Str(e, "NextHop"),
            InterfaceAlias = Str(e, "InterfaceAlias"),
            RouteMetric = Str(e, "RouteMetric"),
            Protocol = Str(e, "Protocol"),
        };

    private static string Str(System.Text.Json.JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) ? v.ToString() : "";

    /// <summary>
    /// 针对目标地址的路由选择（设计文档 4.1 验收：显示本次探针实际绑定地址并与系统路由核对）。
    /// 通过 UDP connect（不发包）让系统给出真实源地址/出口网卡，再与路由表交叉核对。
    /// </summary>
    public static async Task<RouteSelection> SelectRouteAsync(
        System.Net.IPAddress target, int probePort = 33434,
        CancellationToken ct = default)
    {
        string? sourceAddress = null;
        string? explanation = null;

        try
        {
            using var socket = new System.Net.Sockets.Socket(
                target.AddressFamily,
                System.Net.Sockets.SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
            socket.Bind(new System.Net.IPEndPoint(
                target.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    ? System.Net.IPAddress.Any
                    : System.Net.IPAddress.IPv6Any, 0));
            await socket.ConnectAsync(new System.Net.IPEndPoint(target, probePort), ct)
                .ConfigureAwait(false);
            sourceAddress = (socket.LocalEndPoint as System.Net.IPEndPoint)?.Address.ToString();
        }
        catch (Exception ex)
        {
            return new RouteSelection
            {
                Target = target.ToString(),
                Explanation = $"系统路由选择探测失败：{ex.Message}",
            };
        }

        string? nextHop = null;
        string? iface = null;
        try
        {
            var routes = await CollectRoutesAsync(ct).ConfigureAwait(false);
            var matches = new List<(RouteEntry Route, int Prefix)>();
            foreach (var r in routes)
            {
                var parts = r.Destination.Split('/');
                if (!System.Net.IPAddress.TryParse(parts[0], out var net2)) continue;
                int prefix = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 32;
                if (Matches(target, net2, prefix))
                    matches.Add((r, prefix));
            }
            var longest = matches.OrderByDescending(m => m.Prefix).FirstOrDefault().Route;
            if (longest is not null)
            {
                nextHop = longest.NextHop;
                iface = longest.InterfaceAlias;
                explanation = $"最长前缀匹配 {longest.Destination}/{longest.PrefixLength}" +
                    $"（协议 {longest.Protocol}），下一跳 {longest.NextHop}，出口 {longest.InterfaceAlias}";
            }
        }
        catch (Exception ex)
        {
            explanation = $"路由表核对未完成：{ex.Message}";
        }

        return new RouteSelection
        {
            Target = target.ToString(),
            SourceAddress = sourceAddress,
            NextHop = nextHop,
            Interface = iface,
            Explanation = explanation,
        };
    }

    private static bool Matches(System.Net.IPAddress target, System.Net.IPAddress network, int prefix)
    {
        if (target.AddressFamily != network.AddressFamily) return false;
        var t = target.GetAddressBytes();
        var n = network.GetAddressBytes();
        int fullBytes = prefix / 8;
        int remBits = prefix % 8;
        for (int i = 0; i < fullBytes && i < t.Length; i++)
            if (t[i] != n[i]) return false;
        if (remBits > 0 && fullBytes < t.Length)
        {
            int mask = 0xFF << (8 - remBits);
            if ((t[fullBytes] & mask) != (n[fullBytes] & mask)) return false;
        }
        return true;
    }
}
