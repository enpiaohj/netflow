using System.Net;
using NetFlow.Domain;
using NetFlow.Probes;

namespace NetFlow.Application;

/// <summary>单次采样结果。</summary>
public sealed record MonitorSample
{
    public required DateTimeOffset TimeUtc { get; init; }

    /// <summary>结论级别（Pass/Unconfirmed/Fail…）。</summary>
    public required ConclusionLevel Level { get; init; }

    public int? RttMs { get; init; }

    public string Note { get; init; } = "";
}

/// <summary>监测任务定义。</summary>
public sealed record MonitorTask
{
    public required string Id { get; init; }

    public required string Target { get; init; }

    public required int Port { get; init; }

    /// <summary>采样间隔（秒）。低频设计：最小 30 秒。</summary>
    public int IntervalSeconds { get; init; } = 60;

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>指定的源网卡名（null = 系统路由选择）。每次采样按网卡名取当前地址，网卡换 IP 后仍有效。</summary>
    public string? SourceAdapterName { get; init; }
}

/// <summary>
/// 持续监测（设计文档 4.8）：低频定时 TCP 探针。
/// 休眠/断网/进程挂起造成的采样缺口记录为"缺口"而非目标故障；
/// 不在后台抓包；一次采样失败不终止任务。
/// 内存样本上限 {MaxInMemorySamples}，超出后淘汰最旧样本（统计随之滚动）。
/// </summary>
public sealed class ContinuousMonitor : IAsyncDisposable
{
    public const int MaxInMemorySamples = 10000;

    private readonly List<MonitorSample> _samples = [];
    private readonly object _lock = new();
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private DateTimeOffset? _lastSampleUtc;

    public MonitorTask Definition { get; private set; } = null!;

    public bool IsRunning { get; private set; }

    public event EventHandler<MonitorSample>? SampleTaken;
    public event EventHandler<string>? StatusChanged;

    public IReadOnlyList<MonitorSample> Samples
    {
        get { lock (_lock) return _samples.ToArray(); }
    }

    public void Start(MonitorTask task)
    {
        if (IsRunning) throw new InvalidOperationException("监测已在运行");
        if (task.IntervalSeconds < 30)
            throw new ArgumentException("监测间隔最小 30 秒（低频设计，避免对目标造成压力）");

        Definition = task;
        _cts = new CancellationTokenSource();
        IsRunning = true;
        _loop = Task.Run(() => LoopAsync(_cts.Token));
        StatusChanged?.Invoke(this, $"监测已启动：{task.Target}:{task.Port}，每 {task.IntervalSeconds}s 采样");
    }

    public async Task StopAsync()
    {
        if (!IsRunning) return;
        _cts?.Cancel();
        if (_loop is not null)
        {
            try { await _loop.ConfigureAwait(false); } catch (OperationCanceledException) { }
        }
        IsRunning = false;
        StatusChanged?.Invoke(this, "监测已停止");
    }

    private void AddSample(MonitorSample sample)
    {
        lock (_lock)
        {
            _samples.Add(sample);
            if (_samples.Count > MaxInMemorySamples)
                _samples.RemoveRange(0, _samples.Count - MaxInMemorySamples);
        }
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var scheduledAt = DateTimeOffset.UtcNow;

            // 采样缺口检测：实际间隔显著大于计划间隔（休眠/断网/挂起）
            if (_lastSampleUtc is { } last &&
                scheduledAt - last > TimeSpan.FromSeconds(Definition.IntervalSeconds * 2.5))
            {
                AddSample(new MonitorSample
                {
                    TimeUtc = last + TimeSpan.FromSeconds(Definition.IntervalSeconds),
                    Level = ConclusionLevel.Skipped,
                    Note = $"采样缺口（{(int)(scheduledAt - last).TotalSeconds}s 无采样；休眠/断网/挂起，不计入目标故障）",
                });
            }

            await TakeSampleAsync(scheduledAt, ct).ConfigureAwait(false);

            // PeriodicTimer 处理休眠恢复更稳：到点即采，不补偿密集补采
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Definition.IntervalSeconds), ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task TakeSampleAsync(DateTimeOffset at, CancellationToken ct)
    {
        MonitorSample sample;
        try
        {
            if (!IPAddress.TryParse(Definition.Target, out var ip))
            {
                var resolved = await Dns.GetHostAddressesAsync(Definition.Target, ct).ConfigureAwait(false);
                ip = resolved.First();
            }

            IPAddress? source = null;
            if (Definition.SourceAdapterName is { } adapterName)
            {
                // 网卡不可用/无同协议族地址：本次采样记为未确认（异常分支），不当作目标故障
                source = SourceAdapterCatalog.List().FirstOrDefault(o => o.Name == adapterName)
                    ?.PickFor(ip.AddressFamily)
                    ?? throw new InvalidOperationException(
                        $"所选源网卡“{adapterName}”不在线或没有可用的 {ip.AddressFamily} 地址");
            }

            var run = await new TcpConnectProbe().ExecuteAsync(ip, Definition.Port, new ProbeRequest
            {
                RunId = RunId.New(),
                SourceAddress = source,
                Parameters = new ProbeParameters
                {
                    ProbeType = ProbeType.TcpConnect,
                    RequestedTarget = $"{Definition.Target}:{Definition.Port}",
                    Port = Definition.Port,
                    Timeout = Definition.Timeout,
                },
                CancellationToken = ct,
            }).ConfigureAwait(false);

            var verdict = ConclusionEvaluator.Evaluate(run.Transport, run.Protocol);
            sample = new MonitorSample
            {
                TimeUtc = at,
                Level = verdict.Level,
                RttMs = run.Elapsed is { } e ? (int)e.TotalMilliseconds : null,
                Note = run.Transport.ToString(),
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // 采样异常（解析失败等）= 未确认，不终止监测任务
            sample = new MonitorSample
            {
                TimeUtc = at,
                Level = ConclusionLevel.Unconfirmed,
                Note = $"采样异常：{ex.Message}",
            };
        }

        AddSample(sample);
        _lastSampleUtc = at;
        try
        {
            SampleTaken?.Invoke(this, sample);
        }
        catch (Exception ex)
        {
            // 订阅方（UI）异常不能打断监测循环
            AppLog.Warn($"监测事件订阅方异常：{ex.Message}");
        }
    }

    /// <summary>统计摘要（供 UI 顶部指标）。</summary>
    public (int Pass, int Warning, int Fail, int Unconfirmed, int Gaps) Summarize()
    {
        lock (_lock)
        {
            return (
                _samples.Count(s => s.Level == ConclusionLevel.Pass),
                _samples.Count(s => s.Level == ConclusionLevel.Warning),
                _samples.Count(s => s.Level == ConclusionLevel.Fail),
                _samples.Count(s => s.Level == ConclusionLevel.Unconfirmed),
                _samples.Count(s => s.Level == ConclusionLevel.Skipped));
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _cts?.Dispose();
    }
}
