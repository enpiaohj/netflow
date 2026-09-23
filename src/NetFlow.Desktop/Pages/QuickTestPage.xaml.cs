using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Desktop.Services;
using NetFlow.Domain;
using NetFlow.Probes;
using NetFlow.Probes.DnsProtocol;

namespace NetFlow.Desktop.Pages;

public partial class QuickTestPage : UserControl
{
    public ObservableCollection<ResultRow> Results { get; } = [];

    private CancellationTokenSource? _cts;

    public QuickTestPage()
    {
        InitializeComponent();
        ResultGrid.ItemsSource = Results;
        Loaded += (_, _) =>
        {
            if (NavigationState.PendingQuickTestTarget is { } t)
            {
                TargetInput.Text = t;
                NavigationState.PendingQuickTestTarget = null;
            }
        };
    }

    private void TabChanged(object sender, RoutedEventArgs e) { /* 类型选择在启动时读取 */ }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        if (target.Length == 0)
        {
            MessageBox.Show("请输入目标地址", "NetFlow");
            return;
        }
        var port = int.TryParse(PortInput.Text, out var p) ? p : 445;
        var timeout = TimeSpan.FromSeconds(double.TryParse(TimeoutInput.Text, out var s) ? s : 3);

        if (!IPAddress.TryParse(target, out var ip))
        {
            try
            {
                ip = (await Dns.GetHostAddressesAsync(target).ConfigureAwait(true)).First();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"解析失败：{ex.Message}", "NetFlow");
                return;
            }
        }

        StartButton.IsEnabled = false;
        Results.Clear();
        _cts = new CancellationTokenSource();

        var runId = RunId.New();
        var tabs = FindTabRadioButtons();
        string tab = tabs.FirstOrDefault(t => t.IsChecked == true)?.Tag as string ?? "tcpudp";

        try
        {
            var request = new ProbeRequest
            {
                RunId = runId,
                Parameters = new ProbeParameters
                {
                    ProbeType = ProbeType.TcpConnect,
                    RequestedTarget = target,
                    Port = port,
                    Timeout = timeout,
                },
                CancellationToken = _cts.Token,
            };

            switch (tab)
            {
                case "tcpudp":
                    await RunTcpUdpAsync(ip, port, request).ConfigureAwait(true);
                    break;
                case "dns":
                    await RunDnsAsync(target, request).ConfigureAwait(true);
                    break;
                case "http":
                    await RunHttpAsync(target, request).ConfigureAwait(true);
                    break;
                case "ping":
                    await RunPingAsync(ip, request).ConfigureAwait(true);
                    break;
                case "ntp":
                    await RunNtpAsync(ip, request).ConfigureAwait(true);
                    break;
                default:
                    MessageBox.Show("该类型将在后续版本提供", "NetFlow");
                    break;
            }
        }
        finally
        {
            StartButton.IsEnabled = true;
        }
    }

    private async Task RunTcpUdpAsync(IPAddress ip, int port, ProbeRequest request)
    {
        ResultTitle.Text = $"测试结果：TCP {port} / UDP {port}";

        var tcp = await new TcpConnectProbe().ExecuteAsync(ip, port, request).ConfigureAwait(true);
        AddResult(tcp);

        var udp = await new UdpProbe().ExecuteAsync(
            ip, port, new UdpPayload { Text = "NetFlow probe\n", EncodingName = "utf-8" },
            request).ConfigureAwait(true);
        AddResult(udp);
    }

    private async Task RunDnsAsync(string target, ProbeRequest request)
    {
        ResultTitle.Text = $"测试结果：DNS 解析 {target}";
        var dnsServer = await Task.FromResult(FirstSystemDns()) ?? IPAddress.Parse("127.0.0.1");
        foreach (var type in new[] { DnsRecordType.A, DnsRecordType.AAAA })
        {
            var run = await new DnsProbe().ExecuteAsync(dnsServer, target, type, request)
                .ConfigureAwait(true);
            AddResult(run);
        }
    }

    private async Task RunHttpAsync(string target, ProbeRequest request)
    {
        ResultTitle.Text = $"测试结果：HTTP/TLS {target}";
        var uri = target.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? new Uri(target)
            : new Uri($"https://{target}/");

        var httpRun = await new HttpProbe().ExecuteAsync(uri, request).ConfigureAwait(true);
        AddResult(httpRun);

        if (uri.Scheme == "https")
        {
            var tlsRun = await new TlsProbe().ExecuteAsync(
                (await Dns.GetHostAddressesAsync(uri.Host).ConfigureAwait(true)).First(),
                uri.Port == 0 ? 443 : uri.Port,
                uri.Host, request).ConfigureAwait(true);
            AddResult(tlsRun);
        }
    }

    private async Task RunPingAsync(IPAddress ip, ProbeRequest request)
    {
        ResultTitle.Text = $"测试结果：ICMP + 路径 {ip}";
        var ping = await new IcmpProbe().ExecuteAsync(ip, 4, request).ConfigureAwait(true);
        AddResult(ping);

        var trace = await new IcmpProbe().TraceRouteAsync(ip, 10, 1, request).ConfigureAwait(true);
        AddResult(trace);
    }

    private async Task RunNtpAsync(IPAddress ip, ProbeRequest request)
    {
        ResultTitle.Text = $"测试结果：NTP {ip}";
        var run = await new NtpProbe().ExecuteAsync(ip, request).ConfigureAwait(true);
        AddResult(run);
    }

    private void AddResult(ProbeRun run)
    {
        var verdict = ConclusionEvaluator.Evaluate(run.Transport, run.Protocol);
        Results.Add(new ResultRow
        {
            Probe = run.Parameters.ProbeType.ToString(),
            Level = LevelText(verdict.Level),
            Transport = run.Transport.ToString(),
            Protocol = run.Protocol.ToString(),
            Elapsed = run.Elapsed is { } e ? $"{(int)e.TotalMilliseconds} ms" : "—",
        });
        DetailBox.AppendText($"== {run.Parameters.ProbeType}（结论：{LevelText(verdict.Level)}）==\n");
        DetailBox.AppendText(verdict.Rationale + "\n");
        foreach (var obs in run.Observations)
            DetailBox.AppendText($"  {obs.ObservedUtc.LocalDateTime:HH:mm:ss.fff} {obs.Text}\n");
        DetailBox.AppendText("\n");
        DetailBox.ScrollToEnd();
    }

    private static string LevelText(ConclusionLevel level) => level switch
    {
        ConclusionLevel.Pass => "通过",
        ConclusionLevel.Warning => "警告",
        ConclusionLevel.Fail => "失败",
        ConclusionLevel.Unconfirmed => "未确认",
        ConclusionLevel.NotChecked => "未检查",
        ConclusionLevel.Skipped => "跳过",
        ConclusionLevel.Canceled => "已取消",
        _ => level.ToString(),
    };

    private static IPAddress? FirstSystemDns()
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                continue;
            if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                continue;
            var dns = nic.GetIPProperties().DnsAddresses
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (dns is not null) return dns;
        }
        return null;
    }

    private IEnumerable<RadioButton> FindTabRadioButtons()
    {
        // 类型标签在第二个卡片内；用视觉树搜索
        return FindVisual<RadioButton>(this)
            .Where(rb => rb.Tag is string t && t is "tcpudp" or "dns" or "http" or "ping" or "ntp" or "custom"
                && rb.Name != "NavOverview");
    }

    private static IEnumerable<T> FindVisual<T>(System.Windows.Media.Visual root)
        where T : System.Windows.Media.Visual
    {
        if (root is null) yield break;
        var count = System.Windows.Media.VisualTreeHelper.GetChildrenCount(root);
        for (int i = 0; i < count; i++)
        {
            if (System.Windows.Media.VisualTreeHelper.GetChild(root, i) is not System.Windows.Media.Visual child)
                continue;
            if (child is T typed) yield return typed;
            foreach (var sub in FindVisual<T>(child))
                yield return sub;
        }
    }
}

public record ResultRow
{
    public required string Probe { get; init; }
    public required string Level { get; init; }
    public required string Transport { get; init; }
    public required string Protocol { get; init; }
    public required string Elapsed { get; init; }
}
