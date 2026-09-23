using NetFlow.Application;
using NetFlow.Capture;
using NetFlow.Persistence;
using NetFlow.Reporting;
using System.IO;

namespace NetFlow.Desktop.Services;

/// <summary>组合根：应用级服务实例。窗口与页面共享。</summary>
public sealed class AppServices
{
    private static readonly Lazy<AppServices> Lazy = new(() => new AppServices());

    public static AppServices Instance => Lazy.Value;

    public DiagnosisRepository? Repository { get; }

    public DiagnosisOrchestrator Orchestrator { get; }

    public PktmonCaptureController CaptureController { get; }

    public ReportExportService ReportExport { get; }

    public UserTemplateStore UserTemplates { get; }

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
        CaptureController = new PktmonCaptureController(EvidenceRoot);
        ReportExport = new ReportExportService(new RedactionOptions());
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
                $"数据库不可用（{ex.Message}）——诊断功能可用，历史记录暂不可用");
        }
    }

    /// <summary>容错写库：持久层不可用时提示一次并跳过，不抛出。</summary>
    public async Task SaveRunSafeAsync(Domain.DiagnosisRun run, CancellationToken ct = default)
    {
        if (!PersistenceReady)
        {
            PublishStatus($"历史未保存：数据库不可用（{PersistenceError}）");
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
            PublishStatus($"历史保存失败：{ex.Message}（已采集证据与报告文件不受影响）");
        }
    }

    public void PublishStatus(string message) => StatusMessage?.Invoke(this, message);
}
