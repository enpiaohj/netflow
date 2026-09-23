using NetFlow.Domain;

namespace NetFlow.Desktop;

/// <summary>
/// UI 文本统一辅助（设计文档 3.1：状态词统一、无响应显示"—"不显示伪造 0ms）。
/// 各页面共用，避免多处实现漂移。
/// </summary>
public static class UiText
{
    public static string Level(ConclusionLevel level) => level switch
    {
        ConclusionLevel.Pass => "通过",
        ConclusionLevel.Warning => "警告",
        ConclusionLevel.Fail => "失败",
        ConclusionLevel.Unconfirmed => "未确认",
        ConclusionLevel.NotChecked => "未检查",
        ConclusionLevel.Skipped => "跳过",
        ConclusionLevel.Canceled => "已取消",
        _ => level.ToString(),
    };

    /// <summary>耗时显示：null/未完成一律"—"。</summary>
    public static string Elapsed(TimeSpan? elapsed) =>
        elapsed is { } e ? $"{(int)e.TotalMilliseconds} ms" : "—";

    public static string LevelOf(ProbeRun run) =>
        Level(ConclusionEvaluator.Evaluate(run.Transport, run.Protocol).Level);
}
