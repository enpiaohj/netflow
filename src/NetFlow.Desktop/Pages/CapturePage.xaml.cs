using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
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

    public CapturePage()
    {
        InitializeComponent();
        PacketGrid.ItemsSource = Packets;
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        if (!System.Net.IPAddress.TryParse(target, out var ip))
        {
            MessageBox.Show("过滤目标必须是 IP 地址", "NetFlow");
            return;
        }

        var capability = await PktmonCaptureController.DetectCapabilityAsync(CancellationToken.None)
            .ConfigureAwait(true);
        if (!capability.Available)
        {
            MessageBox.Show($"Pktmon 不可用：{capability.Error}", "NetFlow",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _activeRunId = RunId.New();
        _cts = new CancellationTokenSource();
        StartButton.IsEnabled = false;
        CaptureHint.Text = $"抓包中…（runId {_activeRunId}；最长 10 分钟，环形缓冲 256 MB）";

        var (started, reason) = await AppServices.Instance.CaptureController
            .StartAsync(_activeRunId.Value, ip, _cts.Token).ConfigureAwait(true);
        if (started)
        {
            StopButton.IsEnabled = true;
        }
        else
        {
            CaptureHint.Text = reason ?? "抓包未启动";
            StartButton.IsEnabled = true;
        }
    }

    private async void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (_activeRunId is null) return;
        StopButton.IsEnabled = false;

        var (path, note) = await AppServices.Instance.CaptureController
            .StopAsync(_activeRunId.Value, _cts?.Token ?? CancellationToken.None).ConfigureAwait(true);
        _lastPcapng = path;
        CaptureHint.Text = note ?? "已停止";
        StartButton.IsEnabled = true;

        if (path is not null)
            await LoadPcapngAsync(path).ConfigureAwait(true);
    }

    private async void Import_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = "PCAPNG|*.pcapng|全部文件|*.*" };
        if (dialog.ShowDialog() != true) return;
        await LoadPcapngAsync(dialog.FileName).ConfigureAwait(true);
    }

    private async Task LoadPcapngAsync(string path)
    {
        try
        {
            var analysis = await Task.Run(() => PcapngAnalyzer.Analyze(path)).ConfigureAwait(true);

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

            PacketTitle.Text = $"数据包列表（{analysis.Packets.Count} 包，显示前 {Packets.Count}）";
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
