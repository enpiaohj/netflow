using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Desktop.Services;
using NetFlow.Domain;
using NetFlow.Probes;

namespace NetFlow.Desktop.Pages;

public partial class BatchPage : UserControl
{
    public ObservableCollection<BatchRow> Rows { get; } = [];

    private CancellationTokenSource? _cts;

    public BatchPage()
    {
        InitializeComponent();
        BatchGrid.ItemsSource = Rows;
    }

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        var targets = TargetsInput.Text.Split('\n', StringSplitOptions.RemoveEmptyEntries |
            StringSplitOptions.TrimEntries)
            .Select(t => t.Trim())
            .Where(t => t.Length > 0)
            .ToList();
        if (targets.Count == 0) return;

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
                Level = LevelText(verdict.Level),
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
}

public record BatchRow
{
    public required string Target { get; init; }
    public required string Level { get; init; }
    public required string Transport { get; init; }
    public required string Protocol { get; init; }
    public required string Elapsed { get; init; }
    public required string Detail { get; init; }
}
