using System.Windows;

namespace NetFlow.Desktop.Services;

/// <summary>
/// 全局活动任务指示（设计文档 3.1：顶栏始终可见任务状态；
/// 切换页面不停止任务，用户需要在任何页面看到"任务运行中"并能跳回去）。
/// </summary>
public static class ActivityState
{
    private sealed class Activity(string pageKey, string label)
    {
        public string PageKey { get; } = pageKey;
        public string Label { get; } = label;
    }

    private static readonly Dictionary<object, Activity> Activities = new();
    private static readonly object Lock = new();

    /// <summary>活动集合变化（含空=无活动任务）。</summary>
    public static event EventHandler? Changed;

    public static void Begin(object owner, string pageKey, string label)
    {
        lock (Lock) Activities[owner] = new Activity(pageKey, label);
        Changed?.Invoke(null, EventArgs.Empty);
    }

    public static void End(object owner)
    {
        lock (Lock) Activities.Remove(owner);
        Changed?.Invoke(null, EventArgs.Empty);
    }

    public static IReadOnlyList<(string PageKey, string Label)> Current
    {
        get
        {
            lock (Lock) return Activities.Values.Select(a => (a.PageKey, a.Label)).ToArray();
        }
    }
}
