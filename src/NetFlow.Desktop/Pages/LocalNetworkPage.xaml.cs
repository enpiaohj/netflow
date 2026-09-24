using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Desktop.Services;
using NetFlow.Windows;

namespace NetFlow.Desktop.Pages;

public partial class LocalNetworkPage : UserControl
{
    public ObservableCollection<AdapterRow> Adapters { get; } = [];
    public ObservableCollection<SocketEndpointInfo> Listeners { get; } = [];
    public ObservableCollection<FirewallRow> FirewallRules { get; } = [];

    public LocalNetworkPage()
    {
        InitializeComponent();
        AdapterGrid.ItemsSource = Adapters;
        ListenerGrid.ItemsSource = Listeners;
        FirewallGrid.ItemsSource = FirewallRules;
        UiState.Bind(RouteTargetInput, "ip");
        Loaded += async (_, _) => await LoadAsync().ConfigureAwait(true);
    }

    private async Task LoadAsync()
    {
        var adapters = await Task.Run(() => NetworkProfileCollector.CollectAdapters()).ConfigureAwait(true);
        Adapters.Clear();
        foreach (var a in adapters.Where(a => !a.IsLoopback))
        {
            Adapters.Add(new AdapterRow
            {
                Name = a.Name,
                Status = AdapterStatusText(a.Status),
                Ipv4 = string.Join(", ", a.Ipv4Addresses),
                Prefixes = string.Join(", ", a.Ipv4Prefixes),
                Gateways = string.Join(", ", a.Gateways),
                Dns = string.Join(", ", a.DnsServers),
                Mac = a.MacAddress ?? "",
            });
        }
        ProxyText.Text = NetworkProfileCollector.GetProxyStatus();

        try
        {
            var endpoints = await Task.Run(() => TcpTableReader.GetTcpEndpoints()).ConfigureAwait(true);
            Listeners.Clear();
            foreach (var ep in endpoints.Where(e => e.State == "LISTENING").Take(300))
                Listeners.Add(ep);
        }
        catch (Exception ex)
        {
            AppServices.Instance.PublishStatus($"无法读取端口列表：{ex.Message}");
        }
    }

    private static string AdapterStatusText(System.Net.NetworkInformation.OperationalStatus status) => status switch
    {
        System.Net.NetworkInformation.OperationalStatus.Up => "已连接",
        System.Net.NetworkInformation.OperationalStatus.Down => "已断开",
        System.Net.NetworkInformation.OperationalStatus.NotPresent => "设备不存在",
        System.Net.NetworkInformation.OperationalStatus.LowerLayerDown => "下层断开",
        System.Net.NetworkInformation.OperationalStatus.Dormant => "休眠",
        System.Net.NetworkInformation.OperationalStatus.Testing => "测试中",
        _ => "未知",
    };

    // 防火墙枚举值：兼容名称与数字两种输出（旧版脚本以数字输出）
    private static string DirectionText(string v) => v switch
    {
        "Inbound" or "1" => "入站",
        "Outbound" or "2" => "出站",
        _ => v,
    };

    private static string ActionText(string v) => v switch
    {
        "Allow" or "2" => "允许",
        "Block" or "4" => "阻止",
        "NotConfigured" or "0" => "未配置",
        _ => v,
    };

    private static string ProtocolText(string v) => v switch
    {
        "Any" or "256" or "" => "任意",
        "6" => "TCP",
        "17" => "UDP",
        "1" => "ICMPv4",
        "58" => "ICMPv6",
        _ => v,
    };

    private async void Route_Click(object sender, RoutedEventArgs e)
    {
        if (!IPAddress.TryParse(RouteTargetInput.Text.Trim(), out var target))
        {
            RouteResult.Text = "请输入有效的 IP 地址";
            RouteTargetInput.Focus();
            return;
        }
        UiState.Remember(RouteTargetInput, "ip");
        RouteResult.Text = "正在查询…";
        var selection = await NetworkProfileCollector.SelectRouteAsync(target)
            .ConfigureAwait(true);
        RouteResult.Text =
            $"目标：{selection.Target}\n" +
            $"源地址：{selection.SourceAddress ?? "—"}\n" +
            $"下一跳：{selection.NextHop ?? "—"}\n" +
            $"出口接口：{selection.Interface ?? "—"}\n" +
            $"路由匹配：{selection.Explanation ?? "—"}\n";
    }

    private async void Firewall_Click(object sender, RoutedEventArgs e)
    {
        FirewallRules.Clear();
        try
        {
            var rules = await Task.Run(() => FirewallReader.CollectRulesAsync(
                maxRules: 300)).ConfigureAwait(true);
            foreach (var r in rules)
            {
                FirewallRules.Add(new FirewallRow
                {
                    DisplayName = r.DisplayName,
                    Direction = DirectionText(r.Direction),
                    Action = ActionText(r.Action),
                    Protocol = ProtocolText(r.Protocol),
                    LocalPorts = r.LocalPorts,
                    Program = r.Program,
                    Enabled = r.Enabled ? "是" : "否",
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"无法读取防火墙规则：{ex.Message}", "NetFlow");
        }
    }
}

public record AdapterRow
{
    public required string Name { get; init; }
    public required string Status { get; init; }
    public required string Ipv4 { get; init; }
    public required string Prefixes { get; init; }
    public required string Gateways { get; init; }
    public required string Dns { get; init; }
    public required string Mac { get; init; }
}

public record FirewallRow
{
    public required string DisplayName { get; init; }
    public required string Direction { get; init; }
    public required string Action { get; init; }
    public required string Protocol { get; init; }
    public required string LocalPorts { get; init; }
    public required string Program { get; init; }
    public required string Enabled { get; init; }
}
