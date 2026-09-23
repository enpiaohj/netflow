using NetFlow.Domain;
using NetFlow.Reporting;

namespace NetFlow.Application;

/// <summary>报告导出服务：写入报告文件并登记为产物（设计文档第 9 节）。</summary>
public sealed class ReportExportService
{
    private readonly RedactionOptions? _redaction;

    public ReportExportService(RedactionOptions? redaction = null)
    {
        _redaction = redaction;
    }

    /// <summary>导出 HTML/JSON/CSV 三件套到 runId 目录，返回产物清单。</summary>
    public IReadOnlyList<Artifact> ExportAll(DiagnosisRun run, string evidenceRoot)
    {
        var dir = Path.Combine(evidenceRoot, run.Id.ToString());
        Directory.CreateDirectory(dir);
        var artifacts = new List<Artifact>();

        artifacts.Add(WriteArtifact(run, Path.Combine(dir, "report.html"),
            ReportBuilder.BuildHtml(run, _redaction), "html"));
        artifacts.Add(WriteArtifact(run, Path.Combine(dir, "report.json"),
            ReportBuilder.BuildJson(run), "json"));
        artifacts.Add(WriteArtifact(run, Path.Combine(dir, "summary.csv"),
            ReportBuilder.BuildCsv(run), "csv"));

        return artifacts;
    }

    private static Artifact WriteArtifact(DiagnosisRun run, string path, string content, string format)
    {
        File.WriteAllText(path, content);
        return new Artifact
        {
            RunId = run.Id,
            Format = format,
            AbsolutePath = path,
            Size = new FileInfo(path).Length,
            Sha256 = RedactionService.Sha256(content),
        };
    }
}
