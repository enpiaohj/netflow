using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Application;
using NetFlow.Probes.DnsProtocol;
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
    private bool _loadingPacks;

    /// <summary>端口包下拉项；Pack 为 null 表示“不使用端口包”。</summary>
    private sealed record PackChoice(PortPack? Pack)
    {
        public override string ToString() => Pack is null
            ? "（不使用端口包）"
            : $"{Pack.Name}（{Pack.Entries.Count} 项）{(Pack.IsBuiltin ? "" : " · 自定义")}";
    }

    public BatchPage()
    {
        InitializeComponent();
        BatchGrid.ItemsSource = Rows;
        SampleStrip.ItemsSource = Strip;
        UiState.Bind(MonitorTargetInput, "hostport");

        // 默认值来自设置
        var settings = AppServices.Instance.Settings.Current;
        foreach (var v in new[] { "1", "2", "4", "8", "16", "32" }) ConcurrencyInput.Items.Add(v);
        ConcurrencyInput.Text = settings.BatchConcurrency.ToString();
        foreach (var v in new[] { "1", "2", "3", "5", "10", "30" }) TimeoutInput.Items.Add(v);
        TimeoutInput.Text = settings.DefaultTimeoutSeconds.ToString("0.##");

        // 设置页修改默认值后立即生效（仅应用发生变化的项）
        _appliedDefaults = settings;
        AppServices.Instance.Settings.Changed += (_, s) => Dispatcher.BeginInvoke(() => ApplyDefaults(s));

        RefreshPackChoices(UiState.GetPreference("batch.pack"));
        if (!AppServices.Instance.PortPacks.IsPersistent)
            PackStatus.Text = "本地数据库不可用，自定义端口包仅在本次运行期间有效。";
    }

    private AppSettings _appliedDefaults;

    private void ApplyDefaults(AppSettings s)
    {
        if (!RunButton.IsEnabled) return;
        var old = _appliedDefaults;
        _appliedDefaults = s;
        if (s.BatchConcurrency != old.BatchConcurrency) ConcurrencyInput.Text = s.BatchConcurrency.ToString();
        if (s.DefaultTimeoutSeconds != old.DefaultTimeoutSeconds) TimeoutInput.Text = s.DefaultTimeoutSeconds.ToString("0.##");
    }

    // ---- 端口包 ----

    private PortPack? SelectedPack => (PackCombo.SelectedItem as PackChoice)?.Pack;

    private void RefreshPackChoices(string? selectId = null)
    {
        _loadingPacks = true;
        try
        {
            var keep = selectId ?? SelectedPack?.Id;
            var choices = new List<PackChoice> { new(null) };
            choices.AddRange(AppServices.Instance.PortPacks.All.Select(p => new PackChoice(p)));
            PackCombo.ItemsSource = choices;
            // keep 为 null（首次打开/未保存过选择）时不能参与匹配：否则会与“不使用端口包”项（Pack 为 null）误匹配
            PackCombo.SelectedItem = (keep is null ? null : choices.FirstOrDefault(c => c.Pack?.Id == keep))
                ?? choices.FirstOrDefault(c => c.Pack?.Id == BuiltinPortPacks.All[0].Id)
                ?? choices[0];
        }
        finally
        {
            _loadingPacks = false;
        }
        LoadEditorFromSelection();
    }

    private void PackCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loadingPacks) return;
        UiState.SetPreference("batch.pack", SelectedPack?.Id);
        LoadEditorFromSelection();
    }

    private void PackManage_Click(object sender, RoutedEventArgs e)
    {
        var show = PackEditor.Visibility != Visibility.Visible;
        PackEditor.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        PageGrid.MinHeight = show ? 880 : 600;
        PackManageButton.Content = show ? "收起端口包管理" : "管理端口包";
        if (show) LoadEditorFromSelection();
    }

    /// <summary>选中端口包 → 编辑区显示其内容（内置包提示只读，建议另存为自定义包）。</summary>
    private void LoadEditorFromSelection()
    {
        if (PackNameInput is null) return;
        var pack = SelectedPack;
        if (pack is null)
        {
            PackNameInput.Text = "";
            PackDescInput.Text = "";
            PackEntriesInput.Text = "";
        }
        else
        {
            PackNameInput.Text = pack.IsBuiltin ? $"{pack.Name}（自定义）" : pack.Name;
            PackDescInput.Text = pack.Description;
            PackEntriesInput.Text = PortPackText.Format(pack.Entries);
        }
        PackSaveButton.IsEnabled = pack is { IsBuiltin: false };
        PackDeleteButton.IsEnabled = pack is { IsBuiltin: false };
        PackStatus.Text = pack is { IsBuiltin: true }
            ? "内置端口包只读，修改后请“另存为”。"
            : AppServices.Instance.PortPacks.IsPersistent ? "" : "本地数据库不可用，自定义端口包仅在本次运行期间有效。";
    }

    private Task SavePackAsync(bool overwrite) => SavePackCoreAsync(overwrite);

    private async Task SavePackCoreAsync(bool overwrite)
    {
        var selected = SelectedPack;
        var existingId = overwrite && selected is { IsBuiltin: false } ? selected.Id : null;
        try
        {
            var pack = await AppServices.Instance.PortPacks.SaveAsync(
                existingId, PackNameInput.Text, PackDescInput.Text, PackEntriesInput.Text).ConfigureAwait(true);
            RefreshPackChoices(pack.Id);
            PackStatus.Text = $"已保存端口包“{pack.Name}”（{pack.Entries.Count} 项）";
        }
        catch (InvalidOperationException ex)
        {
            PackStatus.Text = ex.Message;
        }
        catch (Exception ex)
        {
            AppLog.Error("端口包保存失败", ex);
            PackStatus.Text = $"无法保存：{ex.Message}";
        }
    }

    private async void PackSave_Click(object sender, RoutedEventArgs e) =>
        await SavePackAsync(overwrite: true).ConfigureAwait(true);

    private async void PackSaveAs_Click(object sender, RoutedEventArgs e) =>
        await SavePackAsync(overwrite: false).ConfigureAwait(true);

    private async void PackDelete_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedPack is not { IsBuiltin: false } pack) return;
        var confirm = MessageBox.Show($"确定要删除自定义端口包“{pack.Name}”吗？此操作无法撤销。", "NetFlow",
            MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.OK) return;
        try
        {
            await AppServices.Instance.PortPacks.DeleteAsync(pack.Id).ConfigureAwait(true);
            RefreshPackChoices();
            PackStatus.Text = $"已删除“{pack.Name}”";
        }
        catch (Exception ex)
        {
            PackStatus.Text = $"无法删除：{ex.Message}";
        }
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
        UiState.Remember(MonitorTargetInput, "hostport");
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
                SourceAdapterName = SourceSelection.SelectedAdapterName,
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

    private void Stop_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        BatchHint.Text = "";
        var lines = TargetsInput.Text.Split('\n');
        var expansion = PortPackExpander.Expand(lines, SelectedPack);
        if (expansion.Targets.Count == 0)
        {
            BatchHint.Text = expansion.Errors.Count > 0
                ? string.Join("；", expansion.Errors)
                : "请输入主机，并选择端口包或使用 host:port 格式。";
            TargetsInput.Focus();
            return;
        }
        if (expansion.Errors.Count > 0)
            BatchHint.Text = "已忽略无效项：" + string.Join("；", expansion.Errors);

        int concurrency = Math.Clamp(int.TryParse(ConcurrencyInput.Text, out var c) ? c : 8, 1, 32);
        var timeoutSeconds = double.TryParse(TimeoutInput.Text, out var s) && s is > 0 and <= 60 ? s : 3;
        var timeout = TimeSpan.FromSeconds(timeoutSeconds);

        RunButton.IsEnabled = false;
        StopButton.IsEnabled = true;
        Rows.Clear();
        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        var runId = RunId.New();
        ActivityState.Begin(this, "batch", $"批量任务（{expansion.Targets.Count} 项）");

        // 先列出全部测试项（排队中），完成一项更新一项，便于查看整体进度
        var rowIndex = new Dictionary<BatchTarget, int>();
        foreach (var t in expansion.Targets)
        {
            rowIndex[t] = Rows.Count;
            Rows.Add(new BatchRow { Host = t.Host, Service = t.Entry.Display, Level = "等待中", Transport = "", Elapsed = "", Detail = "" });
        }

        var dnsCache = new System.Collections.Concurrent.ConcurrentDictionary<string, Task<IPAddress>>(
            StringComparer.OrdinalIgnoreCase);
        var done = 0;
        using var throttler = new SemaphoreSlim(concurrency);
        try
        {
            SummaryText.Text = $"正在检测：0 / {expansion.Targets.Count}";
            var tasks = expansion.Targets.Select(async t =>
            {
                try
                {
                    await throttler.WaitAsync(token).ConfigureAwait(true);
                }
                catch (OperationCanceledException)
                {
                    SetRow(rowIndex[t], t, Cancelled());
                    return;
                }

                try
                {
                    var result = await RunOneAsync(runId, t, timeout, dnsCache, token).ConfigureAwait(true);
                    SetRow(rowIndex[t], t, result);
                }
                finally
                {
                    throttler.Release();
                    SummaryText.Text = $"正在检测：{Interlocked.Increment(ref done)} / {expansion.Targets.Count}";
                }
            });
            await Task.WhenAll(tasks).ConfigureAwait(true);
        }
        finally
        {
            ActivityState.End(this);
            RunButton.IsEnabled = true;
            StopButton.IsEnabled = false;
        }

        var passed = Rows.Count(r => r.Level == "通过");
        SummaryText.Text = $"检测完成：{passed} 通过 / {Rows.Count - passed} 需关注 / 共 {Rows.Count} 项" +
            (token.IsCancellationRequested ? "（已取消，未执行的项标记为“已取消”）" : "");
    }

    private void SetRow(int index, BatchTarget target, BatchRow result) =>
        Rows[index] = result with { Host = target.Host, Service = target.Entry.Display };

    private static BatchRow Cancelled() => new()
    {
        Host = "", Service = "", Level = "已取消", Transport = "", Elapsed = "—", Detail = "任务已取消，未执行",
    };

    private static BatchRow Unconfirmed(string detail) => new()
    {
        Host = "", Service = "", Level = "未确认", Transport = "", Elapsed = "—", Detail = detail,
        LevelBrush = UiText.LevelBrush(ConclusionLevel.Unconfirmed),
    };

    private async Task<BatchRow> RunOneAsync(
        RunId runId, BatchTarget target, TimeSpan timeout,
        System.Collections.Concurrent.ConcurrentDictionary<string, Task<IPAddress>> dnsCache,
        CancellationToken ct)
    {
        try
        {
            // 同一主机只解析一次（端口包会对同一主机测试多个端口）
            var ip = IPAddress.TryParse(target.Host, out var direct)
                ? direct
                : await dnsCache.GetOrAdd(target.Host, async h => (await Dns.GetHostAddressesAsync(h).ConfigureAwait(false)).First())
                    .ConfigureAwait(true);

            var (source, sourceError) = SourceSelection.Resolve(ip.AddressFamily);
            if (sourceError is not null) return Unconfirmed(sourceError);

            var entry = target.Entry;
            ProbeRequest Request(ProbeType type) => new()
            {
                RunId = runId,
                SourceAddress = source,
                Parameters = new ProbeParameters
                {
                    ProbeType = type,
                    RequestedTarget = $"{target.Host}:{entry.Port}",
                    Port = entry.Port,
                    Timeout = timeout,
                },
                CancellationToken = ct,
            };

            ProbeRun run;
            if (entry.Protocol == PortProtocol.Tcp)
            {
                run = await new TcpConnectProbe().ExecuteAsync(ip, entry.Port, Request(ProbeType.TcpConnect))
                    .ConfigureAwait(true);
            }
            else if (entry.Port == 123)
            {
                // UDP 123 走 NTP 协议请求：比“发包无回应 = 未确认”更能说明问题
                run = await new NtpProbe().ExecuteAsync(ip, Request(ProbeType.Ntp)).ConfigureAwait(true);
            }
            else
            {
                run = await new UdpProbe().ExecuteAsync(
                    ip, entry.Port, new UdpPayload { Text = "NetFlow probe\n", EncodingName = "utf-8" },
                    Request(ProbeType.UdpDatagram)).ConfigureAwait(true);
            }

            var verdict = ConclusionEvaluator.Evaluate(run.Transport, run.Protocol);
            return new BatchRow
            {
                Host = "", Service = "",
                Level = UiText.Level(verdict.Level),
                LevelBrush = UiText.LevelBrush(verdict.Level),
                Transport = UiText.Transport(run.Transport),
                Elapsed = UiText.Elapsed(run.Elapsed),
                Detail = verdict.Rationale,
            };
        }
        catch (OperationCanceledException)
        {
            return Cancelled();
        }
        catch (Exception ex)
        {
            return Unconfirmed($"无法完成检测：{ex.Message}");
        }
    }
}

public record BatchRow
{
    public required string Host { get; init; }
    public required string Service { get; init; }
    public required string Level { get; init; }
    public System.Windows.Media.Brush LevelBrush { get; init; } =
        new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x94, 0xA3, 0xB8));
    public required string Transport { get; init; }
    public required string Elapsed { get; init; }
    public required string Detail { get; init; }
}

public record SampleStripItem
{
    public required System.Windows.Media.Brush Color { get; init; }
    public required string Note { get; init; }
}
