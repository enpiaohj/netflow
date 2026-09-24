using NetFlow.Application;
using NetFlow.Application.Ai;
using NetFlow.Capture;
using NetFlow.Persistence;
using NetFlow.Reporting;
using System.IO;

using NetFlow.Domain;

namespace NetFlow.Desktop.Services;

/// <summary>组合根：应用级服务实例。窗口与页面共享。</summary>
public sealed class AppServices
{
    private static readonly Lazy<AppServices> Lazy = new(() => new AppServices());

    public static AppServices Instance => Lazy.Value;

    public DiagnosisRepository? Repository { get; }

    public DiagnosisOrchestrator Orchestrator { get; }

    public PktmonCaptureController CaptureController { get; }

    /// <summary>报告导出服务；脱敏开关变化时重建，见 <see cref="Settings"/>。</summary>
    public ReportExportService ReportExport { get; private set; }

    public UserTemplateStore UserTemplates { get; }

    /// <summary>应用设置（SQLite 持久化）。</summary>
    public AppSettingsStore Settings { get; }

    /// <summary>端口包（内置 + 自定义，自定义存 SQLite）。</summary>
    public PortPackStore PortPacks { get; }

    /// <summary>AI 深入分析（DeepSeek）。</summary>
    public AiAnalysisService Ai { get; }

    /// <summary>证据与抓包根目录：%LOCALAPPDATA%\NetFlow</summary>
    public string EvidenceRoot { get; }

    public string DatabasePath { get; }

    /// <summary>
    /// 持久层是否可用。数据库损坏/被占用时为 false：
    /// 诊断能力照常运行，历史与报告索引降级（每次尝试写库都会在状态栏提示一次）。
    /// </summary>
    public bool PersistenceReady { get; private set; } = true;

    public string? PersistenceError { get; private set; }

    /// <summary>全局状态提示（顶栏）。</summary>
    public event EventHandler<string>? StatusMessage;

    private AppServices()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        EvidenceRoot = Path.Combine(appData, "NetFlow", "evidence");
        DatabasePath = Path.Combine(appData, "NetFlow", "netflow.db");
        Directory.CreateDirectory(EvidenceRoot);

        Orchestrator = new DiagnosisOrchestrator();
        Orchestrator.StatusChanged += (_, msg) => StatusMessage?.Invoke(this, msg);
        // 抓包宿主：以主程序自身（--capture-host）提权运行，单文件 exe 即可抓包；
        // 取不到自身路径时才退回同目录的 NetFlow.CaptureHost.exe
        CaptureController = Environment.ProcessPath is { } self
            ? new PktmonCaptureController(EvidenceRoot, self, PktmonCaptureController.SelfHostSwitch)
            : new PktmonCaptureController(EvidenceRoot);
        UserTemplates = new UserTemplateStore();

        try
        {
            Repository = new DiagnosisRepository(DatabasePath);
            Repository.InitializeAsync().GetAwaiter().GetResult();
            PersistenceReady = true;
        }
        catch (Exception ex)
        {
            // 数据库不可用不阻止诊断：探针/抓包/报告照常，只损失历史与索引
            Repository = null!;
            PersistenceReady = false;
            PersistenceError = ex.Message;
            StatusMessage?.Invoke(this,
                $"无法访问本地数据库（{ex.Message}）。诊断功能不受影响，历史记录暂不可用。");
        }

        // 依赖数据库的服务：数据库不可用时降级为仅内存（设置/端口包本次运行内有效）
        var dataRepo = PersistenceReady ? Repository : null;
        Settings = new AppSettingsStore(dataRepo);
        PortPacks = new PortPackStore(dataRepo);
        Ai = new AiAnalysisService(Settings);

        // 报告脱敏开关来自设置，变化后重建导出服务
        ReportExport = CreateReportExport(Settings.Current);
        Settings.Changed += (_, s) => ReportExport = CreateReportExport(s);
    }

    private static ReportExportService CreateReportExport(AppSettings settings) =>
        new(new RedactionOptions { Enabled = settings.RedactionEnabled });

    /// <summary>容错写库：持久层不可用时提示一次并跳过，不抛出。</summary>
    public async Task SaveRunSafeAsync(Domain.DiagnosisRun run, CancellationToken ct = default)
    {
        if (!PersistenceReady || Repository is null)
        {
            PublishStatus($"历史记录未保存：无法访问本地数据库（{PersistenceError}）");
            return;
        }
        try
        {
            await Repository.SaveRunAsync(run, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            PersistenceError = ex.Message;
            AppLog.Error("写库失败", ex);
            PublishStatus($"无法保存历史记录：{ex.Message}。已生成的证据和报告文件不受影响。");
        }
    }

    public void PublishStatus(string message) => StatusMessage?.Invoke(this, message);
}
