using System.Collections.ObjectModel;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetFlow.Application;
using NetFlow.Application.Ai;
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

    private string _lastTarget = "";
    private IPAddress? _lastSource;
    private string _lastTitle = "快速测试";
    private string _portListKind = "";
    private double _appliedTimeout;

    public QuickTestPage()
    {
        InitializeComponent();
        ResultGrid.ItemsSource = Results;
        UiState.Bind(TargetInput, "target");
        UiState.Bind(DnsServerInput, "dns");
        _appliedTimeout = AppServices.Instance.Settings.Current.DefaultTimeoutSeconds;
        TimeoutInput.Text = _appliedTimeout.ToString("0.##");
        // 设置页修改默认超时后立即生效
        AppServices.Instance.Settings.Changed += (_, s) => Dispatcher.BeginInvoke(() =>
        {
            if (!StartButton.IsEnabled) return;
            if (s.DefaultTimeoutSeconds == _appliedTimeout) return;
            _appliedTimeout = s.DefaultTimeoutSeconds;
            TimeoutInput.Text = _appliedTimeout.ToString("0.##");
        });
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

    private RadioButton[] TypeRadios => [TabTcp, TabUdp, TabDns, TabHttp, TabPing, TabNtp];

    private string CurrentTab =>
        TypeRadios.FirstOrDefault(rb => rb.IsChecked == true)?.Tag?.ToString() ?? "tcp";

    private void Type_Checked(object sender, RoutedEventArgs e) => UpdateTypeUi();

    /// <summary>按测试类型显隐参数并更新说明：端口仅 TCP/UDP 使用，其余类型不展示无关输入。</summary>
    private void UpdateTypeUi()
    {
        // Checked 事件在 InitializeComponent 期间即会触发，此时后续控件尚未创建
        if (PortPanel is null || TypeHint is null || UdpModePanel is null || DnsServerPanel is null) return;

        var tab = CurrentTab;
        PortPanel.Visibility = tab is "tcp" or "udp" ? Visibility.Visible : Visibility.Collapsed;
        UdpModePanel.Visibility = tab == "udp" ? Visibility.Visible : Visibility.Collapsed;
        DnsServerPanel.Visibility = tab == "dns" ? Visibility.Visible : Visibility.Collapsed;
        if (tab is "tcp" or "udp") LoadPortPresets(tab);
        if (tab == "dns") LoadDnsServers();

        TypeHint.Text = tab switch
        {
            "udp" => "发送 UDP 探测包。无应答记为“未确认”，不代表端口关闭。123 端口可同时执行原始 UDP 与 NTP 协议测试。",
            "dns" => "向 DNS 服务器查询 A/AAAA 记录（默认使用源网卡的 DNS）。NXDOMAIN 表示服务器有响应，但域名不存在。",
            "http" => "默认使用 HTTPS 并检查 TLS 证书，也可输入完整 URL。",
            "ping" => "发送 4 次 ICMP Echo 并追踪路径（最多 10 跳），经所选源网卡（IPv4）发出。无应答不等于主机不可达。",
            "ntp" => "向目标发送 NTP 请求（UDP 123）。",
            _ => "测试 TCP 连接。连通仅表示传输层成功，不代表服务可用。",
        };
    }

    /// <summary>端口下拉：TCP 与 UDP 各用一套常见端口（带中文服务名）；保留用户已输入的端口。</summary>
    private void LoadPortPresets(string tab)
    {
        if (_portListKind == tab) return;

        var list = tab == "udp" ? WellKnownPorts.Udp : WellKnownPorts.Tcp;
        var oldList = tab == "udp" ? WellKnownPorts.Tcp : WellKnownPorts.Udp;
        var text = PortInput.Text.Trim();
        var current = WellKnownPorts.ParsePort(text);
        // 当前文本若是上一个协议的预置项（如从 TCP 切到 UDP 时的“445 SMB 文件共享”），换成新协议的默认项；
        // 用户手输的自定义端口则保留
        var wasPreset = text.Length == 0 || oldList.Any(p => p.Display == text) || _portListKind == "";
        PortInput.Items.Clear();
        foreach (var p in list) PortInput.Items.Add(p.Display);

        var match = current is { } c ? list.FirstOrDefault(p => p.Port == c) : null;
        PortInput.Text = match?.Display
            ?? (wasPreset || current is null ? list[0].Display : current.ToString()!);
        _portListKind = tab;
    }

    /// <summary>DNS 服务器下拉：所选源网卡的 DNS 排前面，其次是其他网卡的 DNS。</summary>
    private void LoadDnsServers()
    {
        var servers = DnsServersFor(SourceSelection.SelectedAdapterName)
            .Concat(DnsServersFor(null)).Select(a => a.ToString()).Distinct().ToList();
        var typed = DnsServerInput.Text;
        DnsServerInput.Items.Clear();
        foreach (var server in servers) DnsServerInput.Items.Add(server);
        DnsServerInput.Text = string.IsNullOrWhiteSpace(typed) ? servers.FirstOrDefault() ?? "" : typed;
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
        if (tab is "tcp" or "udp")
        {
            if (WellKnownPorts.ParsePort(PortInput.Text) is not { } p)
            {
                SetError("端口应为 1–65535");
                PortInput.Focus();
                return;
            }
            port = p;
        }

        // UDP 测试方式：0 自动 / 1 仅原始 UDP / 2 仅 NTP / 3 两者
        var udpMode = 1;
        if (tab == "udp")
        {
            var selected = UdpModeInput.SelectedIndex;
            udpMode = selected == 0 ? (port == 123 ? 3 : 1) : selected;
            if (udpMode is 2 or 3 && port != 123)
            {
                SetError("NTP 固定使用 UDP 123，请将端口改为 123 或选择“原始 UDP”");
                PortInput.Focus();
                return;
            }
        }

        // DNS 服务器：手动指定优先，否则用所选源网卡的 DNS
        IPAddress? dnsServer = null;
        if (tab == "dns")
        {
            var typedServer = DnsServerInput.Text.Trim();
            if (typedServer.Length > 0)
            {
                if (!IPAddress.TryParse(typedServer, out dnsServer))
                {
                    SetError("请输入有效的 DNS 服务器 IP 地址");
                    DnsServerInput.Focus();
                    return;
                }
            }
            else
            {
                dnsServer = DnsServersFor(SourceSelection.SelectedAdapterName).FirstOrDefault()
                    ?? DnsServersFor(null).FirstOrDefault();
                if (dnsServer is null)
                {
                    SetError("未找到可用的 DNS 服务器，请手动输入");
                    DnsServerInput.Focus();
                    return;
                }
            }
        }

        if (!double.TryParse(TimeoutInput.Text, out var timeoutSec) || timeoutSec is <= 0 or > 60)
        {
            SetError("超时应大于 0 且不超过 60 秒");
            TimeoutInput.Focus();
            return;
        }
        var timeout = TimeSpan.FromSeconds(timeoutSec);

        // 仅需要目标 IP 的类型才预先解析。DNS/HTTP 类型由探针自行解析：
        // 若在此预解析，域名不存在这类正是要诊断的情形会被提前拦下，URL 形式的目标也会解析失败。
        IPAddress ip = IPAddress.None;
        if (tab is "tcp" or "udp" or "ping" or "ntp")
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
                    SetError($"无法解析主机名：{ex.Message}");
                    return;
                }
            }
        }

        // 源网卡：按目标协议族取所选网卡的地址；DNS/HTTP 类型目标协议族由探针决定，按 IPv4 取
        var family = tab is "tcp" or "udp" or "ping" or "ntp"
            ? ip.AddressFamily
            : AddressFamily.InterNetwork;
        var (source, sourceError) = SourceSelection.Resolve(family);
        if (sourceError is not null)
        {
            SetError(sourceError);
            return;
        }

        UiState.Remember(TargetInput, "target");
        if (dnsServer is not null) UiState.Remember(DnsServerInput, "dns");
        _lastTarget = target;
        _lastSource = source;
        StartButton.IsEnabled = false;
        StopButton.IsEnabled = true;
        Results.Clear();
        _runs.Clear();
        DetailBox.Clear();
        SummaryButton.Visibility = Visibility.Collapsed;
        AiButton.Visibility = Visibility.Collapsed;
        EvidenceTitle.Text = "测试摘要";
        ResultTitle.Text = "正在测试…";
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
            SourceAddress = source,
            CancellationToken = _cts.Token,
        };

        // 每个探针使用与自身类型一致的请求参数，结果表“探针”列才不会全部显示为 TcpConnect
        ProbeRequest For(ProbeType type) =>
            request with { Parameters = request.Parameters with { ProbeType = type } };

        try
        {
            switch (tab)
            {
                case "tcp":
                    ResultTitle.Text = $"测试结果：TCP {port}";
                    AddRun(await new TcpConnectProbe().ExecuteAsync(ip, port!.Value, For(ProbeType.TcpConnect))
                        .ConfigureAwait(true));
                    break;
                case "udp":
                {
                    ResultTitle.Text = udpMode == 3 ? "测试结果：UDP 123（原始 + NTP）" : $"测试结果：UDP {port}";
                    if (udpMode is 1 or 3)
                    {
                        AddRun(await new UdpProbe().ExecuteAsync(
                            ip, port!.Value, new UdpPayload { Text = "NetFlow probe\n", EncodingName = "utf-8" },
                            For(ProbeType.UdpDatagram)).ConfigureAwait(true));
                    }
                    if (udpMode is 2 or 3)
                        AddRun(await new NtpProbe().ExecuteAsync(ip, For(ProbeType.Ntp)).ConfigureAwait(true));
                    break;
                }
                case "dns":
                {
                    ResultTitle.Text = $"测试结果：DNS 解析 {target}";
                    ResultTitle.Text = $"测试结果：DNS 解析 {target}（服务器 {dnsServer}）";
                    foreach (var type in new[] { DnsRecordType.A, DnsRecordType.AAAA })
                    {
                        AddRun(await new DnsProbe().ExecuteAsync(dnsServer!, target, type, For(ProbeType.Dns))
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
            SetError($"执行失败：{ex.Message}");
        }
        finally
        {
            ActivityState.End(this);
            StartButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            if (ResultTitle.Text == "正在测试…")
                ResultTitle.Text = "测试结果";
            _lastTitle = ResultTitle.Text;
            ShowSummary();
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
            Probe = UiText.ProbeTitle(run),
            Level = UiText.Level(level),
            LevelBrush = UiText.LevelBrush(level),
            Transport = UiText.Transport(run.Transport),
            Protocol = UiText.Protocol(run.Protocol),
            Elapsed = UiText.Elapsed(run.Elapsed),
        });
    }

    /// <summary>测试完成后默认显示摘要：各检查项的结论与判定说明，无需先选中某一行。</summary>
    private void ShowSummary()
    {
        ResultGrid.SelectedIndex = -1;
        EvidenceTitle.Text = "测试摘要";
        DetailBox.Clear();
        if (_runs.Count == 0)
        {
            SummaryButton.Visibility = Visibility.Collapsed;
            AiButton.Visibility = Visibility.Collapsed;
            return;
        }

        var levels = _runs.Select(UiText.LevelOfRun).ToList();
        int Count(ConclusionLevel l) => levels.Count(x => x == l);
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"共 {_runs.Count} 项检查：{Count(ConclusionLevel.Pass)} 通过｜{Count(ConclusionLevel.Warning)} 警告｜" +
            $"{Count(ConclusionLevel.Unconfirmed)} 未确认｜{Count(ConclusionLevel.Fail)} 失败");
        sb.AppendLine($"目标：{_lastTarget}");
        sb.AppendLine($"测试源：{(_lastSource is null ? "系统路由选择" : _lastSource.ToString())}");
        sb.AppendLine();
        for (var i = 0; i < _runs.Count; i++)
        {
            var run = _runs[i];
            var verdict = ConclusionEvaluator.Evaluate(run.Transport, run.Protocol);
            sb.AppendLine($"[{UiText.Level(verdict.Level)}] {UiText.ProbeTitle(run)}｜耗时 {UiText.Elapsed(run.Elapsed)}");
            sb.AppendLine($"    {verdict.Rationale}");
            if (run.ProtocolDetail is { Length: > 0 }) sb.AppendLine($"    {run.ProtocolDetail}");
        }
        sb.AppendLine();
        sb.AppendLine("选择左侧结果行查看详细证据。");
        DetailBox.Text = sb.ToString();

        SummaryButton.Visibility = Visibility.Collapsed;
        AiButton.Visibility = Visibility.Visible;
    }

    private void Summary_Click(object sender, RoutedEventArgs e) => ShowSummary();

    private void Ai_Click(object sender, RoutedEventArgs e)
    {
        if (_runs.Count == 0) return;
        AiAnalysisWindow.Open(
            _lastTitle,
            AiPromptBuilder.BuildProbeContext(_lastTitle, _lastTarget, _lastSource?.ToString(), _runs));
    }

    /// <summary>选中结果行 → 证据面板只显示该探针的观察事实（结果与证据不混用）。</summary>
    private void ResultRow_Selected(object sender, SelectionChangedEventArgs e)
    {
        if (ResultGrid.SelectedIndex < 0 || ResultGrid.SelectedIndex >= _runs.Count)
            return;
        var run = _runs[ResultGrid.SelectedIndex];
        EvidenceTitle.Text = $"观察事实：{UiText.ProbeTitle(run)}";
        SummaryButton.Visibility = Visibility.Visible;

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

    /// <summary>指定网卡（null = 全部在线网卡）的 IPv4 DNS 服务器。</summary>
    private static IEnumerable<IPAddress> DnsServersFor(string? adapterName)
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
            if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
            if (adapterName is not null && nic.Name != adapterName) continue;
            foreach (var dns in nic.GetIPProperties().DnsAddresses)
                if (dns.AddressFamily == AddressFamily.InterNetwork) yield return dns;
        }
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
