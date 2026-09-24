namespace NetFlow.Domain;

/// <summary>探针执行结果。结构化结果先于界面渲染与报告生成（设计文档 5.1）。</summary>
public sealed record ProbeRun
{
    public ProbeId Id { get; init; } = ProbeId.New();

    public required RunId RunId { get; init; }

    public required ProbeParameters Parameters { get; init; }

    public ProbeState State { get; set; } = ProbeState.NotRun;

    public DateTimeOffset? StartUtc { get; set; }

    public DateTimeOffset? EndUtc { get; set; }

    /// <summary>传输层观察。</summary>
    public TransportOutcome Transport { get; set; } = TransportOutcome.NotExecuted;

    /// <summary>传输层补充说明（错误码、异常类型、目标 IP 等）。</summary>
    public string? TransportDetail { get; set; }

    /// <summary>协议层观察。</summary>
    public ProtocolOutcome Protocol { get; set; } = ProtocolOutcome.NotExecuted;

    public string? ProtocolDetail { get; set; }

    /// <summary>解析后的目标地址（可能有多个）。</summary>
    public IReadOnlyList<string> ResolvedAddresses { get; set; } = [];

    /// <summary>本次探针实际使用的本机源地址。</summary>
    public string? SourceAddress { get; set; }

    /// <summary>阶段耗时分解。</summary>
    public IReadOnlyList<StageTiming> Stages { get; set; } = [];

    /// <summary>按时间顺序的观察事实。</summary>
    public List<Observation> Observations { get; } = [];

    /// <summary>关联证据 ID。</summary>
    public List<EvidenceId> EvidenceIds { get; } = [];

    /// <summary>探针内部错误码（如 SocketError 枚举名）。用户可读说明放 Observation。</summary>
    public string? ErrorCode { get; set; }

    public void AddObservation(Observation observation) => Observations.Add(observation);

    public TimeSpan? Elapsed =>
        StartUtc is { } s && EndUtc is { } e ? e - s : null;
}
