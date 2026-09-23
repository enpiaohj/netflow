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
                Status = a.Status.ToString(),
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
            AppServices.Instance.PublishStatus($"端口表读取失败：{ex.Message}");
        }
    }

    private async void Route_Click(object sender, RoutedEventArgs e)
    {
        if (!IPAddress.TryParse(RouteTargetInput.Text.Trim(), out var target))
        {
            MessageBox.Show("目标地址需为 IP", "NetFlow");
            return;
        }
        RouteResult.Text = "查询中…";
        var selection = await NetworkProfileCollector.SelectRouteAsync(target)
            .ConfigureAwait(true);
        RouteResult.Text =
            $"目标：{selection.Target}\n" +
            $"本次真实源地址：{selection.SourceAddress ?? "—"}\n" +
            $"下一跳：{selection.NextHop ?? "—"}\n" +
            $"出口接口：{selection.Interface ?? "—"}\n" +
            $"核对：{selection.Explanation ?? "—"}\n";
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
                    Direction = r.Direction,
                    Action = r.Action,
                    Protocol = r.Protocol,
                    LocalPorts = r.LocalPorts,
                    Program = r.Program,
                    Enabled = r.Enabled ? "是" : "否",
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"防火墙规则读取失败：{ex.Message}", "NetFlow");
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
