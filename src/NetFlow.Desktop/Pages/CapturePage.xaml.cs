using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Win32;
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

    /// <summary>自动解析的包数上限：超大抓包只解析前 20 万包（内存与列表可控）。</summary>
    private const int MaxAnalyzedPackets = 200_000;

    public CapturePage()
    {
        InitializeComponent();
        PacketGrid.ItemsSource = Packets;
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        CaptureHint.Text = "";
        var target = TargetInput.Text.Trim();
        if (!System.Net.IPAddress.TryParse(target, out var ip))
        {
            CaptureHint.Text = "过滤目标必须是 IP 地址";
            TargetInput.Focus();
            return;
        }

        // 参数校验（内联，不打断）
        if (!int.TryParse(DurationInput.Text, out var duration) || duration is < 10 or > 3600)
        {
            CaptureHint.Text = "最长时长需为 10–3600 秒";
            DurationInput.Focus();
            return;
        }
        if (!int.TryParse(SnapInput.Text, out var snap) || snap is < 0 or > 1514)
        {
            CaptureHint.Text = "截断长度需为 0–1514 字节（0 = 完整包）";
            SnapInput.Focus();
            return;
        }

        var capability = await PktmonCaptureController.DetectCapabilityAsync(CancellationToken.None)
            .ConfigureAwait(true);
        if (!capability.Available)
        {
            CaptureHint.Text = $"Pktmon 不可用：{capability.Error}";
            return;
        }

        _activeRunId = RunId.New();
        _cts = new CancellationTokenSource();
        StartButton.IsEnabled = false;
        CaptureHint.Text = "正在启动提权采集宿主…";

        var options = new CaptureStartOptions
        {
            MaxDurationSeconds = duration,
            SnapLengthBytes = snap,
        };
        var (started, reason) = await AppServices.Instance.CaptureController
            .StartAsync(_activeRunId.Value, ip, options, _cts.Token).ConfigureAwait(true);
        if (started)
        {
            StopButton.IsEnabled = true;
            _startedUtc = DateTimeOffset.UtcNow;
            StartElapsedTimer();
            CaptureHint.Text = $"抓包中…（runId {_activeRunId}，最长 {duration}s，截断 {(snap == 0 ? "完整包" : snap + "B")}）；" +
                "可切换页面，顶栏可跳回";
        }
        else
        {
            CaptureHint.Text = reason ?? "抓包未启动";
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
            CaptureHint.Text = $"抓包中… 已运行 {elapsed}s / 最长 {duration}s（runId {_activeRunId}）；" +
                "可切换页面，顶栏可跳回";
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
        CaptureHint.Text = "正在停止并等待宿主转换结果（最长等待 60 秒）…";

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
        _lastPcapng = result.PcapngPath;
        CaptureHint.Text = result.Note;
        StartButton.IsEnabled = true;

        if (result.PcapngPath is not null)
            await LoadPcapngAsync(result.PcapngPath).ConfigureAwait(true);
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
        AnalysisBox.AppendText("TShark 深度解析中（只调用本机已安装的 tshark.exe）…\n");
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
            int no = 1;
            foreach (var p in analysis.Packets.Take(2000))
            {
                Packets.Add(new PacketRow
                {
                    No = no++,
                    Source = $"{p.SourceIp}:{(p.SourcePort > 0 ? p.SourcePort : "")}",
                    Destination = $"{p.DestinationIp}:{(p.DestinationPort > 0 ? p.DestinationPort : "")}",
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
                "\n注意：以上为 PCAPNG 的自动分析；Pktmon 多组件观察需按采集层次去重，\n" +
                "时间线上的“超时”是应用事件而非真实收到的数据包。ETL 文件保留为高级诊断证据。\n");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"解析失败：{ex.Message}", "NetFlow");
        }
    }
}

public record PacketRow
{
    public required int No { get; init; }
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public required string Protocol { get; init; }
    public required string Info { get; init; }
}
