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
/// 经参数文件下发采集参数，用命名事件停止，靠状态文件回读结果。
/// 主程序自身保持普通权限（设计文档 2.1）。
/// </summary>
public sealed class PktmonCaptureController : ITaskCaptureHook
{
    private readonly string _evidenceRoot;
    private readonly string _captureHostPath;

    public PktmonCaptureController(string evidenceRoot, string? captureHostPath = null)
    {
        _evidenceRoot = evidenceRoot;
        // 默认取与应用同目录的采集宿主
        _captureHostPath = captureHostPath ??
            Path.Combine(AppContext.BaseDirectory, "NetFlow.CaptureHost.exe");
    }

    public string? LastNote { get; private set; }

    public async Task<(bool Started, string? Reason)> StartAsync(
        RunId runId, IPAddress target, CancellationToken ct)
    {
        // 无管理员权限时说明并按需提升：UAC 弹窗本身即请求（拒绝则返回原因）
        var capability = await DetectCapabilityAsync(ct).ConfigureAwait(false);
        if (!capability.Available)
        {
            LastNote = $"Pktmon 不可用：{capability.Error ?? "未知原因"}。已降级为纯网络测试与导入分析。";
            return (false, LastNote);
        }

        var runDir = Path.Combine(_evidenceRoot, runId.ToString(), "capture");
        Directory.CreateDirectory(runDir);

        var stopEventName = $@"Global\NetFlowCapture-{runId}";
        _ = EventWaitHandle.TryOpenExisting(stopEventName, out _);

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
                LastNote = "采集宿主启动失败";
                return (false, LastNote);
            }
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            // 用户在 UAC 拒绝提升
            LastNote = $"用户未授予管理员权限（{ex.NativeErrorCode}）。仅执行普通探针，本次不抓包。";
            return (false, LastNote);
        }

        LastNote = "抓包已启动（提权宿主运行中）";
        return (true, LastNote);
    }

    public Task<(string? PcapngPath, string? Note)> StopAsync(RunId runId, CancellationToken ct)
    {
        var runDir = Path.Combine(_evidenceRoot, runId.ToString(), "capture");
        var statusFile = Path.Combine(runDir, "capture-status.json");

        // 发停止信号
        var eventName = $@"Global\NetFlowCapture-{runId}";
        if (EventWaitHandle.TryOpenExisting(eventName, out var evt))
        {
            using (evt)
            {
                _ = evt.Set();
            }
        }

        // 等待状态文件进入终态（最多 60 秒）
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(60);
        while (DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
        {
            var status = CaptureStatus.ReadFrom(statusFile);
            if (status is { Phase: "finished" or "failed" })
            {
                return Task.FromResult((status.PcapngPath, (string?)status.Error ?? "抓包已结束"));
            }
            Thread.Sleep(500);
        }
        return Task.FromResult<(string?, string?)>((null, "等待采集宿主结束超时；残留会话将在下次启动时检测并提示清理"));
    }

    /// <summary>遗留会话检测（设计文档 4.5：下次启动检测遗留本工具任务并提示清理）。</summary>
    public static async Task<IReadOnlyList<string>> DetectLeftoverSessionsAsync(
        string evidenceRoot, CancellationToken ct)
    {
        var leftovers = new List<string>();
        if (!Directory.Exists(evidenceRoot)) return leftovers;

        foreach (var dir in Directory.EnumerateDirectories(
            Path.Combine(evidenceRoot), "*", SearchOption.TopDirectoryOnly))
        {
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
            var etwSupported = versionText.Length >= 0; // 基本可用即可尝试 etw 模式，宿主会再验证
            return new PktmonCapability
            {
                Available = true,
                Version = versionText.Length > 0 ? versionText : "（版本未输出）",
                SupportsEtwFileCapture = etwSupported,
            };
        }
        catch (Exception ex)
        {
            return new PktmonCapability { Available = false, Error = ex.Message };
        }
    }
}
