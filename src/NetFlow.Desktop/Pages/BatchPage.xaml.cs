using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Application;
using NetFlow.Desktop.Services;
using NetFlow.Domain;
using NetFlow.Probes;

namespace NetFlow.Desktop.Pages;

public partial class BatchPage : UserControl
{
    public ObservableCollection<BatchRow> Rows { get; } = [];
    public ObservableCollection<SampleStripItem> Strip { get; } = [];

    private CancellationTokenSource? _cts;
    private ContinuousMonitor? _monitor;

    public BatchPage()
    {
        InitializeComponent();
        BatchGrid.ItemsSource = Rows;
        SampleStrip.ItemsSource = Strip;
    }

    // ---- 持续监测 ----

    private async void MonitorStart_Click(object sender, RoutedEventArgs e)
    {
        var target = MonitorTargetInput.Text.Trim();
        if (target.Length == 0)
        {
            MonitorSummary.Text = "请输入监测目标（host:port）";
            MonitorTargetInput.Focus();
            return;
        }
        var parts = target.Split(':');
        int port = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 80;
        int interval = int.TryParse(MonitorIntervalInput.Text, out var i) ? i : 60;

        _monitor = new ContinuousMonitor();
        _monitor.SampleTaken += (_, sample) => Dispatcher.BeginInvoke(() => AddStripItem(sample));
        _monitor.StatusChanged += (_, msg) => Dispatcher.BeginInvoke(() =>
            AppServices.Instance.PublishStatus(msg));

        try
        {
            _monitor.Start(new MonitorTask
            {
                Id = Guid.NewGuid().ToString("N"),
                Target = parts[0],
                Port = port,
                IntervalSeconds = interval,
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "NetFlow");
            return;
        }

        MonitorStartButton.IsEnabled = false;
        MonitorStopButton.IsEnabled = true;
        await Task.CompletedTask.ConfigureAwait(true);
    }

    private async void MonitorStop_Click(object sender, RoutedEventArgs e)
    {
        if (_monitor is not null)
            await _monitor.StopAsync().ConfigureAwait(true);
        MonitorStartButton.IsEnabled = true;
        MonitorStopButton.IsEnabled = false;
        RefreshMonitorSummary();
    }

    private void AddStripItem(MonitorSample sample)
    {
        Strip.Add(new SampleStripItem
        {
            Color = sample.Level switch
            {
                ConclusionLevel.Pass => new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x16, 0xA3, 0x4A)),
                ConclusionLevel.Warning => new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0xD9, 0x77, 0x06)),
                ConclusionLevel.Fail => new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0xDC, 0x26, 0x26)),
                ConclusionLevel.Skipped => new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x94, 0xA3, 0xB8)),
                _ => new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromRgb(0x6B, 0x72, 0x80)),
            },
            Note = $"{sample.TimeUtc.ToLocalTime():HH:mm:ss} {sample.Level} {sample.Note}" +
                (sample.RttMs is { } rtt ? $" {rtt}ms" : ""),
        });
        RefreshMonitorSummary();
    }

    private void RefreshMonitorSummary()
    {
        if (_monitor is null) return;
        var (pass, warn, fail, unconfirmed, gaps) = _monitor.Summarize();
        MonitorSummary.Text = _monitor.IsRunning
            ? $"运行中｜通过 {pass}｜警告 {warn}｜失败 {fail}｜未确认 {unconfirmed}｜采样缺口 {gaps}（缺口不计入目标故障）"
            : $"已停止｜通过 {pass}｜失败 {fail}｜未确认 {unconfirmed}｜采样缺口 {gaps}";
    }

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        var targets = TargetsInput.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries |
            StringSplitOptions.TrimEntries)
            .Select(t => t.Trim())
            .Where(t => t.Length > 0)
            .ToList();
        if (targets.Count == 0)
        {
            SummaryText.Text = "请至少输入一个目标（每行 host:port）";
            TargetsInput.Focus();
            return;
        }

        int concurrency = Math.Clamp(int.TryParse(ConcurrencyInput.Text, out var c) ? c : 8, 1, 32);
        var timeout = TimeSpan.FromSeconds(double.TryParse(TimeoutInput.Text, out var s) ? s : 3);

        RunButton.IsEnabled = false;
        Rows.Clear();
        _cts = new CancellationTokenSource();
        var runId = RunId.New();

        using var throttler = new SemaphoreSlim(concurrency);
        var tasks = targets.Select(async t =>
        {
            await throttler.WaitAsync(_cts.Token).ConfigureAwait(true);
            try
            {
                await RunOneAsync(runId, t, timeout).ConfigureAwait(true);
            }
            finally
            {
                throttler.Release();
            }
        });
        await Task.WhenAll(tasks).ConfigureAwait(true);

        SummaryText.Text = $"目标检测矩阵（{Rows.Count(r => r.Level == "通过")} 通过 / " +
            $"{Rows.Count(r => r.Level != "通过")} 需关注 / 共 {Rows.Count}）";
        RunButton.IsEnabled = true;
    }

    private async Task RunOneAsync(RunId runId, string target, TimeSpan timeout)
    {
        var row = new BatchRow { Target = target, Level = "…", Transport = "", Protocol = "", Elapsed = "", Detail = "" };
        Rows.Add(row);

        var parts = target.Split(':');
        var host = parts[0];
        int port = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 80;

        try
        {
            var ip = IPAddress.TryParse(host, out var direct)
                ? direct
                : (await Dns.GetHostAddressesAsync(host).ConfigureAwait(true)).First();

            var run = await new TcpConnectProbe().ExecuteAsync(ip, port, new ProbeRequest
            {
                RunId = runId,
                Parameters = new ProbeParameters
                {
                    ProbeType = ProbeType.TcpConnect,
                    RequestedTarget = target,
                    Port = port,
                    Timeout = timeout,
                },
                CancellationToken = _cts?.Token ?? CancellationToken.None,
            }).ConfigureAwait(true);

            var verdict = ConclusionEvaluator.Evaluate(run.Transport, run.Protocol);
            Rows[Rows.IndexOf(row)] = row with
            {
                Level = UiText.Level(verdict.Level),
                LevelBrush = UiText.LevelBrush(verdict.Level),
                Transport = run.Transport.ToString(),
                Elapsed = run.Elapsed is { } e ? $"{(int)e.TotalMilliseconds} ms" : "—",
                Detail = verdict.Rationale,
            };
        }
        catch (Exception ex)
        {
            Rows[Rows.IndexOf(row)] = row with
            {
                Level = "未确认",
                Detail = $"解析或执行失败：{ex.Message}",
            };
        }
    }

}

public record BatchRow
{
    public required string Target { get; init; }
    public required string Level { get; init; }
    public System.Windows.Media.Brush LevelBrush { get; init; } =
        new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x94, 0xA3, 0xB8));
    public required string Transport { get; init; }
    public required string Protocol { get; init; }
    public required string Elapsed { get; init; }
    public required string Detail { get; init; }
}

public record SampleStripItem
{
    public required System.Windows.Media.Brush Color { get; init; }
    public required string Note { get; init; }
}
