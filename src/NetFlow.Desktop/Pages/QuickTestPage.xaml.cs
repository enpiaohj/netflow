using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetFlow.Application;
using NetFlow.Desktop.Services;
using NetFlow.Domain;
using NetFlow.Probes;
using NetFlow.Probes.DnsProtocol;

namespace NetFlow.Desktop.Pages;

public partial class QuickTestPage : UserControl
{
    public ObservableCollection<ResultRow> Results { get; } = [];

    private CancellationTokenSource? _cts;

    /// <summary>每次运行产生的探针结果，用于结果行与证据联动。</summary>
    private readonly List<ProbeRun> _runs = [];

    public QuickTestPage()
    {
        InitializeComponent();
        ResultGrid.ItemsSource = Results;
        UpdateTypeUi();
        Loaded += (_, _) =>
        {
            if (NavigationState.PendingQuickTestTab is { } tab)
            {
                NavigationState.PendingQuickTestTab = null;
                var radio = TypeRadios.FirstOrDefault(rb => rb.Tag?.ToString() == tab);
                if (radio is not null) radio.IsChecked = true;
            }
            if (NavigationState.PendingQuickTestTarget is { } t)
            {
                TargetInput.Text = t;
                NavigationState.PendingQuickTestTarget = null;
            }
            TargetInput.Focus();
        };
    }

    private RadioButton[] TypeRadios => [TabTcpUdp, TabDns, TabHttp, TabPing, TabNtp];

    private string CurrentTab =>
        TypeRadios.FirstOrDefault(rb => rb.IsChecked == true)?.Tag?.ToString() ?? "tcpudp";

    private void Type_Checked(object sender, RoutedEventArgs e) => UpdateTypeUi();

    /// <summary>按测试类型显隐参数并更新说明：端口仅 TCP/UDP 使用，其余类型不展示无关输入。</summary>
    private void UpdateTypeUi()
    {
        // Checked 事件在 InitializeComponent 期间即会触发，此时后续控件尚未创建
        if (PortPanel is null || TypeHint is null) return;

        var tab = CurrentTab;
        PortPanel.Visibility = tab == "tcpudp" ? Visibility.Visible : Visibility.Collapsed;
        TypeHint.Text = tab switch
        {
            "dns" => "使用本机系统 DNS 服务器查询 A / AAAA 记录。域名不存在（NXDOMAIN）表示 DNS 有响应但查询业务失败。",
            "http" => "未写协议时按 HTTPS 访问并检查 TLS 证书；也可直接填写完整 URL。",
            "ping" => "发送 4 次 ICMP 并追踪路径（最多 10 跳）。ICMP 无回应不等同于主机不可达。",
            "ntp" => "向目标发起 NTP 时间请求。",
            _ => "同时测试 TCP 连接与 UDP 探测。TCP 连通仅代表传输层成功；UDP 无响应为“未确认”，耗时显示“—”而非 0ms。",
        };
    }

    private void SetError(string? message)
    {
        InlineError.Text = message ?? "";
        InlineError.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
    }

    private void TargetInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            Start_Click(sender, e);
        }
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        SetError(null);
        var tab = CurrentTab;
        var target = TargetInput.Text.Trim();
        if (target.Length == 0)
        {
            SetError("请输入目标地址");
            TargetInput.Focus();
            return;
        }

        // 端口仅 TCP/UDP 使用；其他类型端口为“不适用”（null），不做校验
        int? port = null;
        if (tab == "tcpudp")
        {
            if (!int.TryParse(PortInput.Text, out var p) || p is < 1 or > 65535)
            {
                SetError("端口需为 1–65535");
                PortInput.Focus();
                return;
            }
            port = p;
        }

        if (!double.TryParse(TimeoutInput.Text, out var timeoutSec) || timeoutSec is <= 0 or > 60)
        {
            SetError("超时需大于 0 且不超过 60 秒");
            TimeoutInput.Focus();
            return;
        }
        var timeout = TimeSpan.FromSeconds(timeoutSec);

        // 仅需要目标 IP 的类型才预先解析。DNS/HTTP 类型由探针自行解析：
        // 若在此预解析，域名不存在这类正是要诊断的情形会被提前拦下，URL 形式的目标也会解析失败。
        IPAddress ip = IPAddress.None;
        if (tab is "tcpudp" or "ping" or "ntp")
        {
            if (IPAddress.TryParse(target, out var direct))
            {
                ip = direct;
            }
            else
            {
                // 名称解析失败是常见输入问题：内联提示而非弹窗打断
                try
                {
                    ip = (await Dns.GetHostAddressesAsync(target).ConfigureAwait(true)).First();
                }
                catch (Exception ex)
                {
                    SetError($"名称解析失败：{ex.Message}");
                    return;
                }
            }
        }

        StartButton.IsEnabled = false;
        StopButton.IsEnabled = true;
        Results.Clear();
        _runs.Clear();
        DetailBox.Clear();
        EvidenceTitle.Text = "观察事实与证据";
        ResultTitle.Text = "测试中…";
        _cts = new CancellationTokenSource();
        ActivityState.Begin(this, "quicktest", $"快速测试 {target}");

        var runId = RunId.New();
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

        // 每个探针使用与自身类型一致的请求参数，结果表“探针”列才不会全部显示为 TcpConnect
        ProbeRequest For(ProbeType type) =>
            request with { Parameters = request.Parameters with { ProbeType = type } };

        try
        {
            switch (tab)
            {
                case "tcpudp":
                    ResultTitle.Text = $"测试结果：TCP {port} / UDP {port}";
                    AddRun(await new TcpConnectProbe().ExecuteAsync(ip, port!.Value, For(ProbeType.TcpConnect)).ConfigureAwait(true));
                    AddRun(await new UdpProbe().ExecuteAsync(
                        ip, port!.Value, new UdpPayload { Text = "NetFlow probe\n", EncodingName = "utf-8" },
                        For(ProbeType.UdpDatagram)).ConfigureAwait(true));
                    break;
                case "dns":
                {
                    ResultTitle.Text = $"测试结果：DNS 解析 {target}";
                    var dnsServer = FirstSystemDns();
                    if (dnsServer is null)
                    {
                        SetError("未找到系统 DNS 服务器");
                        return;
                    }
                    foreach (var type in new[] { DnsRecordType.A, DnsRecordType.AAAA })
                    {
                        AddRun(await new DnsProbe().ExecuteAsync(dnsServer, target, type, For(ProbeType.Dns))
                            .ConfigureAwait(true));
                    }
                    break;
                }
                case "http":
                {
                    ResultTitle.Text = $"测试结果：HTTP/TLS {target}";
                    var uri = target.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                        ? new Uri(target)
                        : new Uri($"https://{target}/");

                    AddRun(await new HttpProbe().ExecuteAsync(uri, For(ProbeType.Http)).ConfigureAwait(true));

                    if (uri.Scheme == "https")
                    {
                        var tlsIp = (await Dns.GetHostAddressesAsync(uri.Host).ConfigureAwait(true)).First();
                        AddRun(await new TlsProbe().ExecuteAsync(
                            tlsIp, uri.Port == 0 ? 443 : uri.Port, uri.Host, For(ProbeType.Tls)).ConfigureAwait(true));
                    }
                    break;
                }
                case "ping":
                    ResultTitle.Text = $"测试结果：ICMP + 路径 {ip}";
                    AddRun(await new IcmpProbe().ExecuteAsync(ip, 4, For(ProbeType.IcmpPing)).ConfigureAwait(true));
                    AddRun(await new IcmpProbe().TraceRouteAsync(ip, 10, 1, For(ProbeType.TraceRoute)).ConfigureAwait(true));
                    break;
                case "ntp":
                    ResultTitle.Text = $"测试结果：NTP {ip}";
                    AddRun(await new NtpProbe().ExecuteAsync(ip, For(ProbeType.Ntp)).ConfigureAwait(true));
                    break;
            }
        }
        catch (OperationCanceledException)
        {
            ResultTitle.Text = "测试结果（已取消）";
        }
        catch (Exception ex)
        {
            AppLog.Error("快速测试执行异常", ex);
            SetError($"执行异常：{ex.Message}");
        }
        finally
        {
            ActivityState.End(this);
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            if (ResultTitle.Text == "测试中…")
                ResultTitle.Text = "测试结果";
        }
    }

    private void Stop_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

    /// <summary>登记结果：表格一行 + 证据缓存（行选中时展示对应证据）。</summary>
    private void AddRun(ProbeRun run)
    {
        _runs.Add(run);
        var level = UiText.LevelOfRun(run);
        Results.Add(new ResultRow
        {
            Probe = run.Parameters.ProbeType.ToString(),
            Level = UiText.Level(level),
            LevelBrush = UiText.LevelBrush(level),
            Transport = run.Transport.ToString(),
            Protocol = run.Protocol.ToString(),
            Elapsed = UiText.Elapsed(run.Elapsed),
        });
    }

    /// <summary>选中结果行 → 证据面板只显示该探针的观察事实（结果与证据不混用）。</summary>
    private void ResultRow_Selected(object sender, SelectionChangedEventArgs e)
    {
        if (ResultGrid.SelectedIndex < 0 || ResultGrid.SelectedIndex >= _runs.Count)
            return;
        var run = _runs[ResultGrid.SelectedIndex];
        EvidenceTitle.Text = $"观察事实：{run.Parameters.ProbeType}";

        var verdict = ConclusionEvaluator.Evaluate(run.Transport, run.Protocol);
        DetailBox.Clear();
        DetailBox.AppendText($"结论：{UiText.Level(verdict.Level)}\n{verdict.Rationale}\n");
        if (verdict.Limitations.Count > 0)
            DetailBox.AppendText($"限制：{string.Join("；", verdict.Limitations)}\n");
        if (run.ProtocolDetail is not null)
            DetailBox.AppendText($"协议：{run.ProtocolDetail}\n");
        DetailBox.AppendText("\n");
        foreach (var obs in run.Observations)
            DetailBox.AppendText($"  {obs.ObservedUtc.LocalDateTime:HH:mm:ss.fff} {obs.Text}\n");
        DetailBox.ScrollToEnd();
    }

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
}

public record ResultRow
{
    public required string Probe { get; init; }
    public required string Level { get; init; }
    public required System.Windows.Media.Brush LevelBrush { get; init; }
    public required string Transport { get; init; }
    public required string Protocol { get; init; }
    public required string Elapsed { get; init; }
}
