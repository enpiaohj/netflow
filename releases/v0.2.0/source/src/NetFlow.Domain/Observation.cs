namespace NetFlow.Domain;

/// <summary>带时间戳的观察事实。任何 Finding 的基础，一律记录来源与时间。</summary>
public sealed record Observation
{
    public required DateTimeOffset ObservedUtc { get; init; }

    /// <summary>事实内容。应使用"已发送/已收到/未见/超时"等可验证措辞，
    /// 禁止"被防火墙阻断"等归因表述。</summary>
    public required string Text { get; init; }

    /// <summary>观察来源（探针名、外部工具名、事件日志等）。</summary>
    public required string Source { get; init; }

    /// <summary>该观察的视角。</summary>
    public SourceSide Side { get; init; } = SourceSide.Local;

    /// <summary>可选的结构化键值（如 rtt=12、rcode=NXDOMAIN）。</summary>
    public IReadOnlyDictionary<string, string> Attributes { get; init; } =
        new Dictionary<string, string>();

    public static Observation Now(string text, string source, SourceSide side = SourceSide.Local) =>
        new() { ObservedUtc = DateTimeOffset.UtcNow, Text = text, Source = source, Side = side };

    public static Observation Now(
        string text, string source,
        IReadOnlyDictionary<string, string> attributes,
        SourceSide side = SourceSide.Local) =>
        new()
        {
            ObservedUtc = DateTimeOffset.UtcNow,
            Text = text,
            Source = source,
            Side = side,
            Attributes = attributes,
        };
}

/// <summary>阶段耗时。无响应显示 null，不伪造 0ms（设计文档 3.1）。</summary>
public sealed record StageTiming
{
    public required string Stage { get; init; }

    /// <summary>耗时。null 表示该阶段无响应/未发生。</summary>
    public TimeSpan? Duration { get; init; }

    public DateTimeOffset? StartUtc { get; init; }
    public DateTimeOffset? EndUtc { get; init; }

    public string Display => Duration is { } d ? $"{(int)d.TotalMilliseconds} ms" : "—";
}

/// <summary>探针参数快照。执行时固化，进入报告（可复现率 100% 目标）。</summary>
public sealed record ProbeParameters
{
    public required ProbeType ProbeType { get; init; }

    /// <summary>用户输入的原始目标（未经解析）。</summary>
    public required string RequestedTarget { get; init; }

    /// <summary>端口。null 表示不适用（ICMP、本机快照等）。</summary>
    public int? Port { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>其余探针专属参数（查询类型、SNI、绑定地址等）。</summary>
    public IReadOnlyDictionary<string, string> Extra { get; init; } =
        new Dictionary<string, string>();
}
