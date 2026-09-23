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

/// <summary>
/// Pktmon 采集控制器（主程序侧）：通过 UAC 提升一次性宿主子进程，
/// 经参数文件下发采集参数，停止走「命名事件 + 停止文件」双通道，
/// 结果经状态文件回读。主程序自身保持普通权限（设计文档 2.1）。
/// </summary>
public sealed class PktmonCaptureController : ITaskCaptureHook
{
    private readonly string _evidenceRoot;
    private readonly string _captureHostPath;

    public PktmonCaptureController(string evidenceRoot, string? captureHostPath = null)
    {
        _evidenceRoot = evidenceRoot;
        // 默认取与应用同目录的采集宿主；缺失时提前暴露，不在抓包时才失败
        _captureHostPath = captureHostPath ??
            Path.Combine(AppContext.BaseDirectory, "NetFlow.CaptureHost.exe");
    }

    public string? LastNote { get; private set; }

    public static string StopEventNameFor(RunId runId) => $"Local\\NetFlowCapture-{runId}";

    public static string StopFilePathFor(string runDir) =>
        Path.Combine(runDir, "stop.now");

    public async Task<(bool Started, string? Reason)> StartAsync(
        RunId runId, IPAddress target, CancellationToken ct)
    {
        if (!File.Exists(_captureHostPath))
        {
            LastNote = $"采集宿主缺失：{_captureHostPath}。已降级为纯网络测试与导入分析。";
            return (false, LastNote);
        }

        // 无管理员权限时说明并按需提升：UAC 弹窗本身即请求（拒绝则返回原因）
        var capability = await DetectCapabilityAsync(ct).ConfigureAwait(false);
        if (!capability.Available)
        {
            LastNote = $"Pktmon 不可用：{capability.Error ?? "未知原因"}。已降级为纯网络测试与导入分析。";
            return (false, LastNote);
        }

        var runDir = Path.Combine(_evidenceRoot, runId.ToString(), "capture");
        Directory.CreateDirectory(runDir);

        // 停止通道双保险：
        // 1) Local\ 命名事件（本会话内；避免 Global\ 需要全局对象创建特权）。
        //    此处预先创建，提权宿主按名打开；同会话内其他进程理论上可置位该事件，
        //    影响仅限提前停止本任务采集（无越权写入），可接受。
        // 2) 停止文件 runDir\stop.now（宿主轮询），事件通道不可用时兜底。
        var stopEventName = StopEventNameFor(runId);
        try
        {
            if (!EventWaitHandle.TryOpenExisting(stopEventName, out var existing))
            {
                using var created = new EventWaitHandle(false, EventResetMode.ManualReset, stopEventName);
            }
            else
            {
                existing.Dispose();
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Threading.SynchronizationLockException)
        {
            // 事件通道不可用时仍有停止文件兜底，不阻断采集
        }

        // 残留停止文件清理，防止上次任务立即触发本次停止
        var stopFile = StopFilePathFor(runDir);
        if (File.Exists(stopFile)) File.Delete(stopFile);

        var parameters = new CaptureParams
        {
            RunId = runId.ToString(),
            TargetIp = target.ToString(),
            WorkingDirectory = runDir,
            StopEventName = stopEventName,
        };
        var paramsFile = Path.Combine(runDir, "capture-params.json");
        File.WriteAllText(paramsFile, parameters.ToJson());

        var psi = new ProcessStartInfo
        {
            FileName = _captureHostPath,
            Arguments = $"--params \"{paramsFile}\"",
            UseShellExecute = true, // runas 需要
            Verb = "runas",         // 一次性 UAC 提升
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        try
        {
            using var process = Process.Start(psi);
            if (process is null)
            {
                LastNote = "采集宿主启动失败（系统未返回进程句柄）";
                return (false, LastNote);
            }
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            // 用户在 UAC 拒绝提升（1223）或其他启动失败
            LastNote = ex.NativeErrorCode == 1223
                ? "用户未授予管理员权限，本次不抓包，仅执行普通探针。"
                : $"采集宿主启动失败（Win32 错误 {ex.NativeErrorCode}）：{ex.Message}";
            return (false, LastNote);
        }

        LastNote = "抓包已启动（提权宿主运行中）";
        return (true, LastNote);
    }

    public Task<(string? PcapngPath, string? Note)> StopAsync(RunId runId, CancellationToken ct)
    {
        var runDir = Path.Combine(_evidenceRoot, runId.ToString(), "capture");
        var statusFile = Path.Combine(runDir, "capture-status.json");

        // 通道 1：命名事件
        try
        {
            if (EventWaitHandle.TryOpenExisting(StopEventNameFor(runId), out var evt))
            {
                using (evt)
                {
                    _ = evt.Set();
                }
            }
        }
        catch (Exception)
        {
            // 事件通道失败由停止文件兜底
        }

        // 通道 2：停止文件（宿主在等待循环内检测）
        try
        {
            File.WriteAllText(StopFilePathFor(runDir), DateTimeOffset.UtcNow.ToString("o"));
        }
        catch (IOException)
        {
            // 写入失败时事件通道可能已生效；等待循环按超时保护
        }

        // 等待状态文件进入终态（最多 60 秒）
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(60);
        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            var status = CaptureStatus.ReadFrom(statusFile);
            if (status is { Phase: "finished" or "failed" })
            {
                var note = status.Error
                    ?? (status.PcapngPath is null
                        ? "抓包已结束，但 PCAPNG 转换未产出；ETL 原始证据已保留"
                        : "抓包已结束");
                return Task.FromResult<(string?, string?)>((status.PcapngPath, note));
            }
            Thread.Sleep(500);
        }
        return Task.FromResult<(string?, string?)>(
            (null, "等待采集宿主结束超时；残留会话将在下次启动时检测并提示清理"));
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
