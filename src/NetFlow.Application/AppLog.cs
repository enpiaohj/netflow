using System.Text;

namespace NetFlow.Application;

/// <summary>
/// 轻量滚动文件日志（可观测性基线）：
/// - 线程安全；单日一个文件；启动时清理保留期外的旧文件
/// - 不记录凭据与完整敏感载荷（设计文档第 8 节）
/// - 任何日志写入失败静默放弃：日志永远不能反过来打断业务
/// </summary>
public static class AppLog
{
    private const int RetentionDays = 14;
    private static readonly object Lock = new();
    private static string? _logDir;
    private static bool? _enabled;

    /// <summary>初始化（可传 null 关闭日志）。UI 与 CLI 各自调用一次。</summary>
    public static void Initialize(string? logDirectory)
    {
        lock (Lock)
        {
            _logDir = logDirectory;
            _enabled = !string.IsNullOrWhiteSpace(logDirectory);
            if (_enabled == true)
            {
                try
                {
                    Directory.CreateDirectory(_logDir!);
                    CleanOldLogs(_logDir);
                }
                catch
                {
                    _enabled = false;
                }
            }
        }
    }

    public static void Info(string message) => Write("INFO", message);

    public static void Warn(string message) => Write("WARN", message);

    public static void Error(string message, Exception? ex = null) =>
        Write("ERROR", ex is null ? message : $"{message} :: {ex.GetType().Name}: {ex.Message}");

    private static void Write(string level, string message)
    {
        if (_enabled != true) return;
        try
        {
            var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {Scrub(message)}\n";
            lock (Lock)
            {
                if (_logDir is null) return;
                var file = Path.Combine(_logDir, $"netflow-{DateTime.Now:yyyyMMdd}.log");
                File.AppendAllText(file, line, Encoding.UTF8);
            }
        }
        catch
        {
            // 日志写入失败静默放弃（磁盘满/权限等），不影响业务
        }
    }

    /// <summary>敏感内容擦除：凭据样式的键值对不落盘。</summary>
    private static string Scrub(string message)
    {
        if (message.IndexOf("password", StringComparison.OrdinalIgnoreCase) < 0 &&
            message.IndexOf("token", StringComparison.OrdinalIgnoreCase) < 0 &&
            message.IndexOf("authorization", StringComparison.OrdinalIgnoreCase) < 0)
        {
            return message;
        }
        return "[含疑似敏感内容的记录已被抑制]";
    }

    private static void CleanOldLogs(string dir)
    {
        try
        {
            var cutoff = DateTime.Now.AddDays(-RetentionDays);
            foreach (var file in Directory.EnumerateFiles(dir, "netflow-*.log"))
            {
                if (File.GetLastWriteTime(file) < cutoff)
                    File.Delete(file);
            }
        }
        catch
        {
            // 清理失败不影响本次运行
        }
    }
}
