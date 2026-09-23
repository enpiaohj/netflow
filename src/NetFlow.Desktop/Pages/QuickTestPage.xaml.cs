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
        Loaded += (_, _) =>
        {
            if (NavigationState.PendingQuickTestTarget is { } t)
            {
                TargetInput.Text = t;
                NavigationState.PendingQuickTestTarget = null;
            }
        };
    }

    private string CurrentTab =>
        new[] { TabTcpUdp, TabDns, TabHttp, TabPing, TabNtp }
            .FirstOrDefault(rb => rb.IsChecked == true)?.Tag?.ToString() ?? "tcpudp";

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
        InlineError.Text = "";
        var target = TargetInput.Text.Trim();
        if (target.Length == 0)
        {
            InlineError.Text = "请输入目标地址";
            TargetInput.Focus();
            return;
        }

        if (!int.TryParse(PortInput.Text, out var port) || port is < 1 or > 65535)
        {
            InlineError.Text = "端口需为 1–65535";
            PortInput.Focus();
            return;
        }

        if (!double.TryParse(TimeoutInput.Text, out var timeoutSec) || timeoutSec is <= 0 or > 60)
        {
            InlineError.Text = "超时需为 0–60 秒";
            TimeoutInput.Focus();
            return;
        }
        var timeout = TimeSpan.FromSeconds(timeoutSec);

        // 名称解析失败是常见输入问题：内联提示而非弹窗打断
        IPAddress ip;
        if (IPAddress.TryParse(target, out var direct))
        {
            ip = direct;
        }
        else
        {
            try
            {
                ip = (await Dns.GetHostAddressesAsync(target).ConfigureAwait(true)).First();
            }
            catch (Exception ex)
            {
                InlineError.Text = $"名称解析失败：{ex.Message}";
                return;
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

        try
        {
            switch (CurrentTab)
            {
                case "tcpudp":
                    ResultTitle.Text = $"测试结果：TCP {port} / UDP {port}";
                    AddRun(await new TcpConnectProbe().ExecuteAsync(ip, port, request).ConfigureAwait(true));
                    AddRun(await new UdpProbe().ExecuteAsync(
                        ip, port, new UdpPayload { Text = "NetFlow probe\n", EncodingName = "utf-8" },
                        request).ConfigureAwait(true));
                    break;
                case "dns":
                {
                    ResultTitle.Text = $"测试结果：DNS 解析 {target}";
                    var dnsServer = FirstSystemDns();
                    if (dnsServer is null)
                    {
                        InlineError.Text = "未找到系统 DNS 服务器";
                        return;
                    }
                    foreach (var type in new[] { DnsRecordType.A, DnsRecordType.AAAA })
                    {
                        AddRun(await new DnsProbe().ExecuteAsync(dnsServer, target, type, request)
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

                    AddRun(await new HttpProbe().ExecuteAsync(uri, request).ConfigureAwait(true));

                    if (uri.Scheme == "https")
                    {
                        var tlsIp = (await Dns.GetHostAddressesAsync(uri.Host).ConfigureAwait(true)).First();
                        AddRun(await new TlsProbe().ExecuteAsync(
                            tlsIp, uri.Port == 0 ? 443 : uri.Port, uri.Host, request).ConfigureAwait(true));
                    }
                    break;
                }
                case "ping":
                    ResultTitle.Text = $"测试结果：ICMP + 路径 {ip}";
                    AddRun(await new IcmpProbe().ExecuteAsync(ip, 4, request).ConfigureAwait(true));
                    AddRun(await new IcmpProbe().TraceRouteAsync(ip, 10, 1, request).ConfigureAwait(true));
                    break;
                case "ntp":
                    ResultTitle.Text = $"测试结果：NTP {ip}";
                    AddRun(await new NtpProbe().ExecuteAsync(ip, request).ConfigureAwait(true));
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
            InlineError.Text = $"执行异常：{ex.Message}";
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
        Results.Add(new ResultRow
        {
            Probe = run.Parameters.ProbeType.ToString(),
            Level = UiText.LevelOf(run),
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
    public required string Transport { get; init; }
    public required string Protocol { get; init; }
    public required string Elapsed { get; init; }
}
