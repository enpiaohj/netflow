using System.Net;

namespace NetFlow.Domain;

/// <summary>诊断任务生命周期状态（设计文档 7.1 任务状态机）。</summary>
public enum RunState
{
    Draft,
    Preparing,
    Running,
    Finalizing,
    Completed,
    Failed,
    Canceled,
}

/// <summary>诊断任务（设计文档 5.1 DiagnosisRun）。固化执行时快照以保证可复现。</summary>
public sealed class DiagnosisRun
{
    public RunId Id { get; init; } = RunId.New();

    /// <summary>任务生命周期状态。</summary>
    public RunState State { get; set; } = RunState.Draft;

    /// <summary>场景模板快照（模板 ID + 版本 + 步骤定义）。null 表示自由测试。</summary>
    public ScenarioSnapshot? Scenario { get; set; }

    public required string SourceHost { get; set; }

    /// <summary>用户期望的源地址（可选，null=系统自动选择）。</summary>
    public string? RequestedSourceAddress { get; set; }

    /// <summary>本次实际使用的源网卡。</summary>
    public string? Adapter { get; set; }

    public required string RequestedTarget { get; set; }

    public IReadOnlyList<string> ResolvedAddresses { get; set; } = [];

    public DateTimeOffset? StartUtc { get; set; }

    public DateTimeOffset? EndUtc { get; set; }

    public required string AppVersion { get; set; }

    /// <summary>管理员权限状态（执行时快照）。</summary>
    public bool Elevated { get; set; }

    public List<ProbeRun> Probes { get; } = [];

    public List<Finding> Findings { get; } = [];

    public List<Evidence> Evidences { get; } = [];

    public List<Artifact> Artifacts { get; } = [];

    /// <summary>任务终止原因（取消/崩溃/超时等）。正常完成为 null。</summary>
    public string? TerminationReason { get; set; }
}

/// <summary>场景模板快照：执行时从模板定义固化，不随后续模板编辑变化（设计文档 4.7）。</summary>
public sealed record ScenarioSnapshot
{
    public required string TemplateId { get; init; }

    public required string TemplateName { get; init; }

    /// <summary>模板版本（语义化）。规则版本与报告绑定。</summary>
    public required string TemplateVersion { get; init; }

    public required string Direction { get; init; }

    /// <summary>固化后的步骤定义（名称、探针类型、参数、依赖、条件）。</summary>
    public required IReadOnlyList<ScenarioStep> Steps { get; init; }
}

/// <summary>场景步骤定义。</summary>
public sealed record ScenarioStep
{
    public required string Name { get; init; }

    public required ProbeType ProbeType { get; init; }

    /// <summary>参数键值（端口、查询类型、SNI 等）。</summary>
    public IReadOnlyDictionary<string, string> Parameters { get; init; } =
        new Dictionary<string, string>();

    /// <summary>依赖：仅当这些步骤的结论属于 givenLevels 时才执行。</summary>
    public IReadOnlyList<string> DependsOn { get; init; } = [];

    /// <summary>依赖满足条件。空集合 = 无条件执行。</summary>
    public IReadOnlyList<ConclusionLevel> RunWhenLevels { get; init; } = [];

    /// <summary>跳过条件说明（写入结果，模板不适用时说明原因）。</summary>
    public string? SkipReasonHint { get; init; }
}

/// <summary>抓包挂钩：编排器在任务前后调用；由 NetFlow.Capture 提供实现。</summary>
public interface ITaskCaptureHook
{
    /// <summary>启动采集（可能因权限缺失返回 false，并给出原因）。</summary>
    Task<(bool Started, string? Reason)> StartAsync(RunId runId, IPAddress target, CancellationToken ct);

    /// <summary>停止采集并产出文件。返回（pcapng 路径或 null，说明）。</summary>
    Task<(string? PcapngPath, string? Note)> StopAsync(RunId runId, CancellationToken ct);
}

/// <summary>证据记录。原始敏感载荷默认不进入数据库，仅存摘要与路径。</summary>
public sealed record Evidence
{
    public EvidenceId Id { get; init; } = EvidenceId.New();

    public required RunId RunId { get; init; }

    public ProbeId? ProbeId { get; init; }

    public required EvidenceKind Kind { get; init; }

    public required SourceSide Side { get; init; }

    public required DateTimeOffset CapturedUtc { get; init; }

    /// <summary>证据文件相对路径（相对证据根目录）。</summary>
    public string? ArtifactPath { get; init; }

    /// <summary>内容摘要（文本型证据的脱敏正文或文件 SHA-256 前置说明）。</summary>
    public string? Summary { get; init; }

    public string? ContentHash { get; init; }

    public RedactionLevel Redaction { get; init; } = RedactionLevel.Redacted;
}

/// <summary>发现（结论）。每条建议必须对应至少一个事实（设计文档 5.3）。</summary>
public sealed record Finding
{
    public FindingId Id { get; init; } = FindingId.New();

    public required RunId RunId { get; init; }

    public required Severity Severity { get; init; }

    /// <summary>观察事实（≥1 条，否则构造失败）。</summary>
    public required IReadOnlyList<string> ObservedFacts { get; init; }

    /// <summary>可支持的推断（与事实严格分开）。</summary>
    public string? Inference { get; init; }

    /// <summary>限制（视角、采样窗口、时钟偏差等）。</summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];

    /// <summary>下一步建议。</summary>
    public IReadOnlyList<string> NextSteps { get; init; } = [];

    /// <summary>支撑证据 ID。</summary>
    public IReadOnlyList<EvidenceId> SupportingEvidenceIds { get; init; } = [];

    /// <summary>生成该结论的规则版本。</summary>
    public required string RuleVersion { get; init; }

    /// <summary>整体结论级别。</summary>
    public required ConclusionLevel Level { get; init; }
}

/// <summary>证据文件（PCAPNG/ETL/报告等）。</summary>
public sealed record Artifact
{
    public ArtifactId Id { get; init; } = ArtifactId.New();

    public required RunId RunId { get; init; }

    public required string Format { get; init; }

    public required string AbsolutePath { get; init; }

    public long Size { get; init; }

    public string? Sha256 { get; init; }

    public RetentionPolicy Retention { get; init; } = RetentionPolicy.Default;
}
