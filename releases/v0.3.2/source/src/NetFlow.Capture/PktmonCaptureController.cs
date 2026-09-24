using System.Diagnostics;
using System.Net;
using NetFlow.Domain;
using NetFlow.Windows;

namespace NetFlow.Capture;

/// <summary>Pktmon 能力检测结果（M0：OS 能力矩阵，不虚构抓包能力）。</summary>
public sealed record PktmonCapability
{
    public bool Available { get; init; }
    public string? Version { get; init; }
    public bool SupportsEtwFileCapture { get; init; }
    public bool SupportsDropOnlyConversion { get; init; }
    public string? Error { get; init; }
}

/// <summary>抓包启动参数（UI 可配置部分；其余走安全默认值）。</summary>
public sealed record CaptureStartOptions
{
    /// <summary>最长采集时长（秒），范围 10–3600。</summary>
    public int MaxDurationSeconds { get; init; } = 600;

    /// <summary>每包截断长度（字节），0 = 完整包。</summary>
    public int SnapLengthBytes { get; init; } = 128;

    /// <summary>采集模式：<see cref="CaptureParams.RecordMode"/>（默认）或 <see cref="CaptureParams.LiveMode"/>。</summary>
    public string Mode { get; init; } = CaptureParams.RecordMode;

    /// <summary>环形缓冲区（MB），范围 16–1024。</summary>
    public int RingBufferMb { get; init; } = 256;

    public CaptureParams ToParams(string runId, string targetIp, string runDir, string stopEventName) =>
        new()
        {
            RunId = runId,
            TargetIp = targetIp,
            WorkingDirectory = runDir,
            StopEventName = stopEventName,
            MaxDurationSeconds = MaxDurationSeconds,
            SnapLengthBytes = SnapLengthBytes,
            RingBufferMb = RingBufferMb,
            Mode = Mode,
        };
}

/// <summary>停止结果。</summary>
public sealed record CaptureStopResult
{
    public required string? PcapngPath { get; init; }

    public required string Note { get; init; }

    /// <summary>true = 等待宿主结束超时；宿主可能仍在运行，UI 应保留重试手段。</summary>
    public bool TimedOut { get; init; }
}

/// <summary>
/// Pktmon 采集控制器（主程序侧）：通过 UAC 提升一次性宿主子进程，
/// 经参数文件下发采集参数，停止走「命名事件 + 停止文件」双通道，
/// 结果经状态文件回读。主程序自身保持普通权限（设计文档 2.1）。
/// </summary>
public sealed class PktmonCaptureController : ITaskCaptureHook
{
    /// <summary>
    /// 自宿主开关：主程序以该参数（+ --params）重新启动自身作为提权采集宿主，
    /// 这样单个 exe 即可抓包，无需旁边再放 NetFlow.CaptureHost.exe。
    /// </summary>
    public const string SelfHostSwitch = "--capture-host";

    private readonly string _evidenceRoot;
    private readonly string _captureHostPath;
    private readonly string _hostArgumentPrefix;

    /// <summary>本控制器预创建的停止事件句柄：保持存活以维持事件名存在，
    /// 直到停止完成（此前版本创建后立即释放，名称即被销毁）。</summary>
    private EventWaitHandle? _stopEvent;

    /// <param name="captureHostPath">宿主可执行文件；缺省取与应用同目录的 NetFlow.CaptureHost.exe。</param>
    /// <param name="hostArgumentPrefix">宿主参数前缀；自宿主时传 <see cref="SelfHostSwitch"/>。</param>
    public PktmonCaptureController(
        string evidenceRoot, string? captureHostPath = null, string? hostArgumentPrefix = null)
    {
        _evidenceRoot = evidenceRoot;
        _hostArgumentPrefix = string.IsNullOrEmpty(hostArgumentPrefix) ? "" : hostArgumentPrefix + " ";
        // 默认取与应用同目录的采集宿主；缺失时在启动阶段即暴露
        _captureHostPath = captureHostPath ??
            Path.Combine(AppContext.BaseDirectory, "NetFlow.CaptureHost.exe");
    }

    public string? LastNote { get; private set; }

    public static string StopEventNameFor(RunId runId) => $"Local\\NetFlowCapture-{runId}";

    public static string StopFilePathFor(string runDir) =>
        Path.Combine(runDir, "stop.now");

    public static string StatusFilePathFor(string runDir) =>
        Path.Combine(runDir, "capture-status.json");

    /// <summary>实时模式的输出文件（宿主写入、界面轮询读取）。</summary>
    public static string LiveLogPathFor(string runDir) =>
        Path.Combine(runDir, "live.log");

    /// <summary>某次任务的抓包工作目录。</summary>
    public string RunDirFor(RunId runId) =>
        Path.Combine(_evidenceRoot, runId.ToString(), "capture");

    public async Task<(bool Started, string? Reason)> StartAsync(
        RunId runId, IPAddress target, CancellationToken ct) =>
        await StartAsync(runId, target, new CaptureStartOptions(), ct).ConfigureAwait(false);

    public async Task<(bool Started, string? Reason)> StartAsync(
        RunId runId, IPAddress target, CaptureStartOptions options, CancellationToken ct)
    {
        if (!File.Exists(_captureHostPath))
        {
            LastNote = $"找不到抓包程序：{_captureHostPath}。抓包不可用，其他功能不受影响。";
            return (false, LastNote);
        }

        // 无管理员权限时说明并按需提升：UAC 弹窗本身即请求（拒绝则返回原因）
        var capability = await DetectCapabilityAsync(ct).ConfigureAwait(false);
        if (!capability.Available)
        {
            LastNote = $"无法使用 Pktmon：{capability.Error ?? "未知原因"}。抓包不可用，仍可进行网络测试和导入分析。";
            return (false, LastNote);
        }

        var runDir = Path.Combine(_evidenceRoot, runId.ToString(), "capture");
        Directory.CreateDirectory(runDir);

        // 停止通道双保险：
        // 1) Local\ 命名事件（本会话内；避免 Global\ 需要全局对象创建特权）。
        //    句柄保持存活到停止完成，确保事件名在宿主存活期间一直存在。
        // 2) 停止文件 runDir\stop.now（宿主轮询），事件通道不可用时兜底。
        var stopEventName = StopEventNameFor(runId);
        _stopEvent?.Dispose();
        _stopEvent = null;
        try
        {
            _stopEvent = EventWaitHandle.TryOpenExisting(stopEventName, out var existing)
                ? existing
                : new EventWaitHandle(false, EventResetMode.ManualReset, stopEventName);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Threading.SynchronizationLockException)
        {
            // 事件通道不可用时仍有停止文件兜底，不阻断采集
            AppLog.Warn($"停止事件通道不可用，将仅依赖停止文件：{ex.Message}");
        }

        // 残留停止文件清理，防止上次任务立即触发本次停止
        var stopFile = StopFilePathFor(runDir);
        if (File.Exists(stopFile))
        {
            try { File.Delete(stopFile); } catch (IOException) { /* 删除失败不阻断 */ }
        }

        var parameters = options.ToParams(runId.ToString(), target.ToString(), runDir, stopEventName);
        var paramsFile = Path.Combine(runDir, "capture-params.json");
        File.WriteAllText(paramsFile, parameters.ToJson());

        var psi = new ProcessStartInfo
        {
            FileName = _captureHostPath,
            Arguments = $"{_hostArgumentPrefix}--params \"{paramsFile}\"",
            UseShellExecute = true, // runas 需要
            Verb = "runas",         // 一次性 UAC 提升
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        try
        {
            using var process = Process.Start(psi);
            if (process is null)
            {
                LastNote = "无法启动抓包进程。";
                return (false, LastNote);
            }

            // 存活探测：宿主若因部署不完整（缺 DLL）等原因立即退出，
            // 此处即可发现，而不是让 UI 一直显示“抓包中”
            var statusFile = StatusFilePathFor(runDir);
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (DateTime.UtcNow < deadline)
            {
                await Task.Delay(500, ct).ConfigureAwait(false);
                if (File.Exists(statusFile)) break; // 宿主已写出初始状态
                if (process.HasExited)
                {
                    LastNote = $"抓包进程启动后立即退出（代码 {process.ExitCode}）。" +
                        "可能是程序文件不完整，或被安全策略阻止。";
                    AppLog.Error(LastNote ?? "采集宿主立即退出");
                    return (false, LastNote);
                }
            }
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            // 用户在 UAC 拒绝提升（1223）或其他启动失败
            LastNote = ex.NativeErrorCode == 1223
                ? "未获得管理员权限，无法抓包。其他检测不受影响。"
                : $"无法启动抓包进程（Win32 错误 {ex.NativeErrorCode}）：{ex.Message}";
            return (false, LastNote);
        }

        LastNote = "抓包已开始";
        return (true, LastNote);
    }

    /// <summary>
    /// 停止采集并等待宿主写出结果。真异步：等待循环用 Task.Delay，
    /// 不会阻塞调用方线程（此前版本 Thread.Sleep 会让 UI 冻结最多 60 秒）。
    /// </summary>
    public async Task<CaptureStopResult> StopAsync(RunId runId, CancellationToken ct)
    {
        var runDir = Path.Combine(_evidenceRoot, runId.ToString(), "capture");
        var statusFile = StatusFilePathFor(runDir);

        // 通道 1：命名事件
        try
        {
            _stopEvent?.Set();
        }
        catch (Exception ex)
        {
            AppLog.Warn($"停止事件置位失败（由停止文件兜底）：{ex.Message}");
        }

        // 通道 2：停止文件（宿主在等待循环内检测）
        try
        {
            File.WriteAllText(StopFilePathFor(runDir), DateTimeOffset.UtcNow.ToString("o"));
        }
        catch (IOException ex)
        {
            AppLog.Warn($"停止文件写入失败：{ex.Message}");
        }

        // 异步等待状态文件进入终态（最多 60 秒）
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(60);
        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            var status = await Task.Run(() => CaptureStatus.ReadFrom(statusFile), ct)
                .ConfigureAwait(false);
            if (status is { Phase: "finished" or "failed" })
            {
                _stopEvent?.Dispose();
                _stopEvent = null;
                var note = status.Error
                    ?? (status.Mode == CaptureParams.LiveMode
                        ? "实时抓包已结束（未保存文件）"
                        : status.PcapngPath is null
                            ? "抓包已结束，但未能生成 PCAPNG。原始 ETL 文件已保留。"
                            : "抓包已结束");
                return new CaptureStopResult
                {
                    PcapngPath = status.PcapngPath,
                    Note = note,
                    TimedOut = false,
                };
            }
            await Task.Delay(500, ct).ConfigureAwait(false);
        }

        // 超时：宿主可能仍在运行。保留事件句柄，UI 可再次点击停止重试。
        return new CaptureStopResult
        {
            PcapngPath = null,
            Note = "等待抓包进程结束超时。可再次点击“停止”，抓包进程也将在最长时长到达后自动结束。",
            TimedOut = true,
        };
    }

    async Task<(string? PcapngPath, string? Note)> ITaskCaptureHook.StopAsync(
        RunId runId, CancellationToken ct)
    {
        var result = await StopAsync(runId, ct).ConfigureAwait(false);
        return (result.PcapngPath, result.Note);
    }

    /// <summary>遗留会话检测（设计文档 4.5：下次启动检测遗留本工具任务并提示清理）。</summary>
    public static async Task<IReadOnlyList<string>> DetectLeftoverSessionsAsync(
        string evidenceRoot, CancellationToken ct)
    {
        var leftovers = new List<string>();
        if (!Directory.Exists(evidenceRoot)) return leftovers;

        foreach (var dir in Directory.EnumerateDirectories(evidenceRoot, "*", SearchOption.TopDirectoryOnly))
        {
            ct.ThrowIfCancellationRequested();
            var statusFile = Path.Combine(dir, "capture", "capture-status.json");
            var paramsFile = Path.Combine(dir, "capture", "capture-params.json");
            if (File.Exists(paramsFile) && !File.Exists(statusFile))
            {
                leftovers.Add(dir);
                continue;
            }
            if (CaptureStatus.ReadFrom(statusFile) is { } status &&
                status.Phase is not ("finished" or "failed"))
            {
                leftovers.Add(dir);
            }
        }
        await Task.CompletedTask.ConfigureAwait(false);
        return leftovers;
    }

    /// <summary>Pktmon 能力检测（非提权可探测版本与帮助文本）。</summary>
    public static async Task<PktmonCapability> DetectCapabilityAsync(CancellationToken ct)
    {
        if (!File.Exists(ProcessRunner.PktmonPath))
        {
            return new PktmonCapability
            {
                Available = false,
                Error = $"未找到 {ProcessRunner.PktmonPath}（当前 OS 可能无 Pktmon）",
            };
        }

        try
        {
            var version = await ProcessRunner.RunAsync(
                ProcessRunner.PktmonPath, ["--version"], TimeSpan.FromSeconds(10), ct)
                .ConfigureAwait(false);
            if (!version.Succeeded)
            {
                // 某些版本不支持 --version，再试 help
                var help = await ProcessRunner.RunAsync(
                    ProcessRunner.PktmonPath, ["help"], TimeSpan.FromSeconds(10), ct)
                    .ConfigureAwait(false);
                if (!help.Succeeded)
                {
                    return new PktmonCapability
                    {
                        Available = false,
                        Error = $"pktmon 退出码 {version.ExitCode}/{help.ExitCode}（可能被策略限制或 OS 不支持）",
                    };
                }
            }

            var versionText = version.StandardOutput.Trim();
            return new PktmonCapability
            {
                Available = true,
                Version = versionText.Length > 0 ? versionText : "（版本未输出）",
                SupportsEtwFileCapture = true, // 宿主启动时会以实际退出码再验证
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new PktmonCapability { Available = false, Error = ex.Message };
        }
    }
}
