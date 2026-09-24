using System.Windows.Media;
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

    /// <summary>结论徽章底色（白字 pill，对齐概念图状态色）。</summary>
    public static Brush LevelBrush(ConclusionLevel level)
    {
        var color = level switch
        {
            ConclusionLevel.Pass => Color.FromRgb(0x16, 0xA3, 0x4A),
            ConclusionLevel.Warning => Color.FromRgb(0xD9, 0x77, 0x06),
            ConclusionLevel.Fail => Color.FromRgb(0xDC, 0x26, 0x26),
            ConclusionLevel.Unconfirmed => Color.FromRgb(0x64, 0x74, 0x8B),
            ConclusionLevel.NotChecked => Color.FromRgb(0x94, 0xA3, 0xB8),
            ConclusionLevel.Skipped => Color.FromRgb(0x94, 0xA3, 0xB8),
            ConclusionLevel.Canceled => Color.FromRgb(0x6B, 0x72, 0x80),
            _ => Color.FromRgb(0x6B, 0x72, 0x80),
        };
        return new SolidColorBrush(color);
    }

    /// <summary>结论徽章文字（白底彩字，用于浅色场合）。</summary>
    public static Brush LevelForeground(ConclusionLevel level)
    {
        var color = level switch
        {
            ConclusionLevel.Pass => Color.FromRgb(0x16, 0x65, 0x34),
            ConclusionLevel.Warning => Color.FromRgb(0x92, 0x40, 0x0E),
            ConclusionLevel.Fail => Color.FromRgb(0x99, 0x1B, 0x1B),
            ConclusionLevel.Unconfirmed => Color.FromRgb(0x37, 0x41, 0x51),
            _ => Color.FromRgb(0x47, 0x55, 0x69),
        };
        return new SolidColorBrush(color);
    }

    /// <summary>耗时显示：null/未完成一律"—"。</summary>
    public static string Elapsed(TimeSpan? elapsed) =>
        elapsed is { } e ? $"{(int)e.TotalMilliseconds} ms" : "—";

    public static string LevelOf(ProbeRun run) =>
        Level(ConclusionEvaluator.Evaluate(run.Transport, run.Protocol).Level);

    public static ConclusionLevel LevelOfRun(ProbeRun run) =>
        ConclusionEvaluator.Evaluate(run.Transport, run.Protocol).Level;
}
