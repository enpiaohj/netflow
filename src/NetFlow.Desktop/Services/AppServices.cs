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

    public DiagnosisRepository Repository { get; }

    public DiagnosisOrchestrator Orchestrator { get; }

    public PktmonCaptureController CaptureController { get; }

    public ReportExportService ReportExport { get; }

    public UserTemplateStore UserTemplates { get; }

    /// <summary>证据与抓包根目录：%LOCALAPPDATA%\NetFlow</summary>
    public string EvidenceRoot { get; }

    public string DatabasePath { get; }

    /// <summary>全局状态提示（顶栏）。</summary>
    public event EventHandler<string>? StatusMessage;

    private AppServices()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        EvidenceRoot = Path.Combine(appData, "NetFlow", "evidence");
        DatabasePath = Path.Combine(appData, "NetFlow", "netflow.db");
        Directory.CreateDirectory(EvidenceRoot);

        Repository = new DiagnosisRepository(DatabasePath);
        Repository.InitializeAsync().GetAwaiter().GetResult();
        Orchestrator = new DiagnosisOrchestrator();
        Orchestrator.StatusChanged += (_, msg) => StatusMessage?.Invoke(this, msg);
        CaptureController = new PktmonCaptureController(EvidenceRoot);
        ReportExport = new ReportExportService(new RedactionOptions());
        UserTemplates = new UserTemplateStore();
    }

    public void PublishStatus(string message) => StatusMessage?.Invoke(this, message);
}
