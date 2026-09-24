using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
using NetFlow.Application.Ai;
using NetFlow.Capture;
using NetFlow.Desktop.Services;
using NetFlow.Domain;
using NetFlow.Windows;

namespace NetFlow.Desktop.Pages;

public partial class CapturePage : UserControl
{
    public ObservableCollection<PacketRow> Packets { get; } = [];

    private RunId? _activeRunId;
    private string? _lastPcapng;
    private CancellationTokenSource? _cts;
    private DispatcherTimer? _elapsedTimer;
    private DateTimeOffset _startedUtc;

    /// <summary>已触发“到达最长时长自动结束”，避免计时器重复触发停止流程。</summary>
    private bool _autoStopping;

    /// <summary>自动解析的包数上限：超大抓包只解析前 20 万包（内存与列表可控）。</summary>
    private const int MaxAnalyzedPackets = 200_000;

    // ---- 实时显示模式 ----
    private DispatcherTimer? _liveTimer;
    private string? _livePath;
    private long _liveOffset;
    private string _liveRemainder = "";
    private PktmonLiveParser _liveParser = new();
    private bool _liveActive;
    private bool _liveCapped;
    private readonly LiveCounters _counters = new();

    /// <summary>实时列表行数上限；超出后不再追加行，但统计继续。</summary>
    private const int LiveMaxRows = 20_000;

    private sealed class LiveCounters
    {
        public int Total, Tcp, Udp, Dns, Icmp, Arp, Syn, Rst;
    }

    private bool IsLiveMode => ModeInput.SelectedIndex == 1;

    public CapturePage()
    {
        InitializeComponent();
        PacketGrid.ItemsSource = Packets;
        UiState.Bind(TargetInput, "ip");

        // 默认值来自设置
        var settings = AppServices.Instance.Settings.Current;
        foreach (var v in new[] { "10", "30", "60", "120", "300", "600", "1800", "3600" }) DurationInput.Items.Add(v);
        DurationInput.Text = settings.CaptureDurationSeconds.ToString();
        foreach (var v in new[] { "0", "64", "128", "256", "512", "1514" }) SnapInput.Items.Add(v);
        SnapInput.Text = settings.CaptureSnapBytes.ToString();
        ModeInput.SelectedIndex = settings.CaptureMode == "live" ? 1 : 0;
        ModeInput.SelectionChanged += (_, _) => UpdateModeHint();
        UpdateModeHint();
    }

    private void UpdateModeHint()
    {
        if (ModeHint is null) return;
        ModeHint.Text = IsLiveMode
            ? "实时显示：通过 pktmon 实时模式输出数据包，不保存文件；需保存或自动分析请选“记录后分析”。同一数据包在多个组件的重复输出已去重。"
            : "记录后分析：抓包结束后生成 PCAPNG，并自动分析重传、复位、握手失败等异常；到达最长时长自动结束。";
    }

    /// <summary>校验/环境类错误以红色显示，与进行中的状态提示（蓝色）区分。</summary>
    private void ShowCaptureError(string message)
    {
        CaptureHint.Foreground = (System.Windows.Media.Brush)FindResource("StatusFail");
        CaptureHint.Text = message;
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        CaptureHint.Foreground = (System.Windows.Media.Brush)FindResource("PrimaryBrush");
        CaptureHint.Text = "";
        var target = TargetInput.Text.Trim();
        if (!System.Net.IPAddress.TryParse(target, out var ip))
        {
            ShowCaptureError("请输入有效的 IP 地址");
            TargetInput.Focus();
            return;
        }

        UiState.Remember(TargetInput, "ip");

        // 参数校验（内联，不打断）
        if (!int.TryParse(DurationInput.Text, out var duration) || duration is < 10 or > 3600)
        {
            ShowCaptureError("最长时长应为 10–3600 秒");
            DurationInput.Focus();
            return;
        }
        if (!int.TryParse(SnapInput.Text, out var snap) || snap is < 0 or > 1514)
        {
            ShowCaptureError("截断长度应为 0–1514 字节（0 表示完整数据包）");
            SnapInput.Focus();
            return;
        }

        var capability = await PktmonCaptureController.DetectCapabilityAsync(CancellationToken.None)
            .ConfigureAwait(true);
        if (!capability.Available)
        {
            ShowCaptureError($"无法使用 Pktmon：{capability.Error}");
            return;
        }

        _activeRunId = RunId.New();
        _cts = new CancellationTokenSource();
        StartButton.IsEnabled = false;
        CaptureHint.Text = "正在启动抓包…";

        var live = IsLiveMode;
        var options = new CaptureStartOptions
        {
            MaxDurationSeconds = duration,
            SnapLengthBytes = snap,
            Mode = live ? CaptureParams.LiveMode : CaptureParams.RecordMode,
        };
        var (started, reason) = await AppServices.Instance.CaptureController
            .StartAsync(_activeRunId.Value, ip, options, _cts.Token).ConfigureAwait(true);
        if (started)
        {
            StopButton.IsEnabled = true;
            _startedUtc = DateTimeOffset.UtcNow;
            _autoStopping = false;
            ActivityState.Begin(this, "capture", $"{(live ? "实时抓包" : "抓包")} {ip}");
            StartElapsedTimer();
            if (live)
                StartLiveTail(AppServices.Instance.CaptureController.RunDirFor(_activeRunId.Value));
            else
                PacketTitle.Text = "数据包列表";
            CaptureHint.Text = $"正在抓包：最长 {duration} 秒，截断 {(snap == 0 ? "完整数据包" : snap + " 字节")}。" +
                "可切换到其他页面，任务将继续运行。";
        }
        else
        {
            ShowCaptureError(reason ?? "无法启动抓包");
            StartButton.IsEnabled = true;
        }
    }

    private void StartElapsedTimer()
    {
        _elapsedTimer?.Stop();
        _elapsedTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _elapsedTimer.Tick += (_, _) =>
        {
            var elapsed = (int)(DateTimeOffset.UtcNow - _startedUtc).TotalSeconds;
            var duration = int.TryParse(DurationInput.Text, out var d) ? d : 600;

            // 宿主到达最长时长会自行结束采集：这里多留 2 秒余量后自动走“停止并解析”流程，
            // 不再需要用户手动点停止才能看到结果
            if (elapsed >= duration + 2 && !_autoStopping)
            {
                _autoStopping = true;
                CaptureHint.Text = $"已达到最长时长（{duration} 秒），正在停止抓包并分析…";
                Stop_Click(this, new RoutedEventArgs());
                return;
            }
            if (_autoStopping) return;

            CaptureHint.Text = $"正在抓包：已运行 {elapsed} 秒，最长 {duration} 秒。" +
                "可切换到其他页面，任务将继续运行。";
        };
        _elapsedTimer.Start();
    }

    private void StopElapsedTimer()
    {
        _elapsedTimer?.Stop();
        _elapsedTimer = null;
    }

    private async void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (_activeRunId is null) return;
        StopButton.IsEnabled = false;
        CaptureHint.Text = "正在停止抓包并生成结果（最长 60 秒）…";

        CaptureStopResult result;
        try
        {
            result = await AppServices.Instance.CaptureController
                .StopAsync(_activeRunId.Value, _cts?.Token ?? CancellationToken.None)
                .ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            // 页面级取消（应用退出等）：保留重试能力
            StopButton.IsEnabled = true;
            return;
        }

        if (result.TimedOut)
        {
            // 宿主可能仍在运行：保留停止按钮供重试，不清空 runId。
            // 停掉已用时计时器，避免它持续覆盖提示文本
            StopElapsedTimer();
            CaptureHint.Text = result.Note;
            StopButton.IsEnabled = true;
            return;
        }

        StopElapsedTimer();
        ActivityState.End(this);
        _lastPcapng = result.PcapngPath;
        CaptureHint.Text = result.Note;
        StartButton.IsEnabled = true;

        if (_liveActive)
        {
            await FinishLiveTailAsync().ConfigureAwait(true);
            return;
        }

        if (result.PcapngPath is not null)
            await LoadPcapngAsync(result.PcapngPath).ConfigureAwait(true);
    }

    // ---- 实时显示：轮询宿主写出的 live.log ----

    private void StartLiveTail(string runDir)
    {
        StopLiveTimer();
        Packets.Clear();
        _counters.Total = _counters.Tcp = _counters.Udp = _counters.Dns = _counters.Icmp = _counters.Arp = 0;
        _counters.Syn = _counters.Rst = 0;
        _liveParser = new PktmonLiveParser();
        _livePath = PktmonCaptureController.LiveLogPathFor(runDir);
        _liveOffset = 0;
        _liveRemainder = "";
        _liveCapped = false;
        _liveActive = true;
        AnalysisTitle.Text = "实时统计";
        AnalysisBox.Text = "等待数据包…可在“快速测试”中向过滤 IP 发起测试。";
        PacketTitle.Text = "实时数据包（0 包）";

        _liveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _liveTimer.Tick += (_, _) => PumpLive();
        _liveTimer.Start();
    }

    private void StopLiveTimer()
    {
        _liveTimer?.Stop();
        _liveTimer = null;
    }

    /// <summary>读取 live.log 新增内容 → 解析 → 追加到列表并刷新统计。</summary>
    private bool PumpLive()
    {
        if (_livePath is null || !File.Exists(_livePath)) return false;

        string text;
        try
        {
            using var fs = new FileStream(_livePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length <= _liveOffset) return false;
            fs.Seek(_liveOffset, SeekOrigin.Begin);
            var toRead = (int)Math.Min(fs.Length - _liveOffset, 2_000_000);
            var buffer = new byte[toRead];
            var read = fs.Read(buffer, 0, toRead);
            _liveOffset += read;
            // 宿主按 Latin-1 逐字节写入：这里同样按 Latin-1 读，ASCII 部分（时间/方向/地址）不受本地化影响
            text = _liveRemainder + System.Text.Encoding.Latin1.GetString(buffer, 0, read);
        }
        catch (IOException)
        {
            return false; // 文件暂时被占用，下个周期再读
        }

        var lines = text.Split('\n');
        _liveRemainder = lines[^1]; // 末尾可能是半行
        var added = 0;
        for (var i = 0; i < lines.Length - 1; i++)
        {
            if (!_liveParser.TryFeed(lines[i].TrimEnd('\r'), out var packet) || packet is null) continue;
            added++;
            Count(packet);
            if (Packets.Count < LiveMaxRows)
                Packets.Add(ToRow(_counters.Total, packet));
            else
                _liveCapped = true;
        }

        if (added > 0)
        {
            PacketTitle.Text = $"实时数据包（{_counters.Total} 包" +
                (_liveCapped ? $"，列表仅显示前 {LiveMaxRows} 行，统计仍在继续" : "") + "）";
            RenderLiveStats();
            if (AutoScrollCheck.IsChecked == true && Packets.Count > 0)
                PacketGrid.ScrollIntoView(Packets[^1]);
        }
        return added > 0;
    }

    private void Count(LivePacket p)
    {
        _counters.Total++;
        switch (p.Protocol)
        {
            case "TCP":
                _counters.Tcp++;
                if (p.Info.StartsWith("[SYN]", StringComparison.Ordinal)) _counters.Syn++;
                if (p.Info.StartsWith("[RST", StringComparison.Ordinal)) _counters.Rst++;
                break;
            case "UDP": _counters.Udp++; break;
            case "DNS": _counters.Dns++; break;
            case "ICMP" or "ICMPv6": _counters.Icmp++; break;
            case "ARP": _counters.Arp++; break;
        }
    }

    private static PacketRow ToRow(int no, LivePacket p) => new()
    {
        No = no,
        Time = p.Time,
        Direction = p.Direction,
        Source = p.Source,
        Destination = p.Destination,
        Protocol = p.Protocol,
        Info = p.Info,
    };

    private void RenderLiveStats()
    {
        var c = _counters;
        AnalysisBox.Text =
            $"截至 {DateTime.Now:HH:mm:ss}：共 {c.Total} 个数据包（已去重）\n\n" +
            $"TCP  {c.Tcp}（其中 SYN {c.Syn}、RST {c.Rst}）\n" +
            $"UDP  {c.Udp}\n" +
            $"DNS  {c.Dns}\n" +
            $"ICMP {c.Icmp}\n" +
            $"ARP  {c.Arp}\n\n" +
            "提示：RST 明显增多通常表示对端拒绝或会话被重置；仅有 SYN 而无 SYN,ACK，说明请求未获应答" +
            "（无法区分对端未监听与被过滤）。\n" +
            "实时模式不保存文件；需保存与自动分析请使用“记录后分析”。";
    }

    /// <summary>停止后再读几轮，确保宿主最后写出的内容都进入列表，然后给出收尾说明。</summary>
    private async Task FinishLiveTailAsync()
    {
        for (var i = 0; i < 6; i++)
        {
            if (!PumpLive() && i >= 2) break;
            await Task.Delay(300).ConfigureAwait(true);
        }
        StopLiveTimer();
        _liveActive = false;
        RenderLiveStats();
        PacketTitle.Text = $"实时数据包（共 {_counters.Total} 包，已结束）";
    }

    /// <summary>PCAPNG 时间戳（微秒，通常为 Unix 时间）→ 本地时间；不像绝对时间的按相对秒显示。</summary>
    private static string FormatTimestamp(ulong micros) =>
        micros > 946_684_800_000_000UL
            ? DateTimeOffset.FromUnixTimeMilliseconds((long)(micros / 1000)).ToLocalTime().ToString("HH:mm:ss.fff")
            : $"{micros / 1_000_000.0:0.000}s";

    private void Ai_Click(object sender, RoutedEventArgs e)
    {
        if (Packets.Count == 0 && string.IsNullOrWhiteSpace(AnalysisBox.Text))
        {
            ShowCaptureError("没有可分析的内容，请先抓包或导入 PCAPNG。");
            return;
        }
        var lines = Packets.Take(150).Select(p =>
            $"{p.Time} {p.Direction} {p.Source} → {p.Destination} {p.Protocol} {p.Info}".Replace("  ", " ").Trim());
        var title = IsLiveMode || _liveActive ? "实时抓包" : "抓包分析";
        AiAnalysisWindow.Open(title,
            AiPromptBuilder.BuildCaptureContext(title, AnalysisBox.Text, lines));
    }

    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "PCAPNG|*.pcapng|全部文件|*.*" };
        if (dialog.ShowDialog() != true) return;
        await LoadPcapngAsync(dialog.FileName).ConfigureAwait(true);
    }

    private async void Tshark_Click(object sender, RoutedEventArgs e)
    {
        var path = _lastPcapng;
        if (path is null || !File.Exists(path))
        {
            var dialog = new OpenFileDialog { Filter = "PCAPNG|*.pcapng|全部文件|*.*" };
            if (dialog.ShowDialog() != true) return;
            path = dialog.FileName;
        }

        AnalysisBox.Clear();
        AnalysisBox.AppendText("正在使用 TShark 解析（调用本机已安装的 tshark.exe）…\n");
        try
        {
            var (hierarchy, detail) = await Task.Run(() => TsharkAdapter.DeepAnalyzeAsync(path))
                .ConfigureAwait(true);
            AnalysisBox.Clear();
            AnalysisBox.AppendText($"文件：{path}\n\n== 协议层级统计 ==\n{hierarchy}\n\n== 详细字段（前 300 行）==\n{detail}\n");
        }
        catch (Exception ex)
        {
            AnalysisBox.AppendText($"TShark 解析失败：{ex.Message}\n内置 PCAPNG 分析不受影响。\n");
        }
    }

    private async Task LoadPcapngAsync(string path)
    {
        try
        {
            // 限最大解析包数：超大抓包内存与耗时可控；分析口径在结果中说明
            var analysis = await Task.Run(
                () => PcapngAnalyzer.Analyze(path, MaxAnalyzedPackets)).ConfigureAwait(true);

            Packets.Clear();
            AnalysisTitle.Text = "异常分析";
            int no = 1;
            foreach (var p in analysis.Packets.Take(2000))
            {
                Packets.Add(new PacketRow
                {
                    No = no++,
                    Time = FormatTimestamp(p.TimestampUs),
                    // 无端口的协议（如 ICMP）只显示 IP，避免多余的冒号
                    Source = p.SourcePort > 0 ? $"{p.SourceIp}:{p.SourcePort}" : $"{p.SourceIp}",
                    Destination = p.DestinationPort > 0 ? $"{p.DestinationIp}:{p.DestinationPort}" : $"{p.DestinationIp}",
                    Protocol = p.Protocol,
                    Info = p.Info,
                });
            }

            var truncated = analysis.Packets.Count >= MaxAnalyzedPackets
                ? $"（已达到解析上限 {MaxAnalyzedPackets} 包，统计基于前 {MaxAnalyzedPackets} 包）"
                : "";
            PacketTitle.Text = $"数据包列表（{analysis.Packets.Count} 包{truncated}，显示前 {Packets.Count}）";
            AnalysisBox.Clear();
            AnalysisBox.AppendText($"文件：{path}\n\n");
            foreach (var f in analysis.Findings)
                AnalysisBox.AppendText($"• {f}\n");
            if (analysis.Findings.Count == 0)
                AnalysisBox.AppendText("（未发现异常模式）\n");
            AnalysisBox.AppendText(
                "\n说明：以上为 PCAPNG 的自动分析结果。\n" +
                "时间线中的“超时”为应用事件，并非实际收到的数据包。原始 ETL 文件已保留，可供进一步分析。\n");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"无法解析：{ex.Message}", "NetFlow");
        }
    }
}

public record PacketRow
{
    public required int No { get; init; }
    public string Time { get; init; } = "";
    public string Direction { get; init; } = "";
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public required string Protocol { get; init; }
    public required string Info { get; init; }
}
