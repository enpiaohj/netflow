using System.Diagnostics;
using System.Text;

namespace NetFlow.Windows;

/// <summary>外部命令执行结果（设计文档 7.3：退出码、权限和版本进入 Evidence）。</summary>
public sealed record ProcessRunResult
{
    public required string ExecutablePath { get; init; }
    public required IReadOnlyList<string> Arguments { get; init; }
    public required int ExitCode { get; init; }
    public required string StandardOutput { get; init; }
    public required string StandardError { get; init; }
    public required TimeSpan Duration { get; init; }
    public bool TimedOut { get; init; }
    public bool Succeeded => ExitCode == 0 && !TimedOut;
}

/// <summary>
/// 外部命令执行器。设计文档约束：固定可执行文件路径、参数数组（不拼接命令行）、
/// 可取消进程树、输出大小限制、执行时间限制。
/// </summary>
public static class ProcessRunner
{
    /// <summary>Windows PowerShell 固定路径（系统组件，不做 PATH 搜索）。</summary>
    public const string WindowsPowerShellPath =
        @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    public const string PktmonPath =
        @"C:\Windows\System32\pktmon.exe";

    public static async Task<ProcessRunResult> RunAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken ct = default,
        string? workingDirectory = null,
        int maxOutputBytes = 8 * 1024 * 1024)
    {
        var psi = new ProcessStartInfo
        {
            FileName = executablePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory ?? Environment.SystemDirectory,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var arg in arguments)
            psi.ArgumentList.Add(arg);

        using var process = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var sw = Stopwatch.StartNew();
        bool timedOut = false;

        process.Start();

        var outTask = PumpAsync(process.StandardOutput, stdout, maxOutputBytes);
        var errTask = PumpAsync(process.StandardError, stderr, maxOutputBytes);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            timedOut = true;
            try { process.Kill(entireProcessTree: true); } catch { /* 已退出 */ }
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(entireProcessTree: true); } catch { /* 已退出 */ }
            throw;
        }

        await Task.WhenAll(outTask, errTask).ConfigureAwait(false);
        sw.Stop();

        return new ProcessRunResult
        {
            ExecutablePath = executablePath,
            Arguments = arguments,
            ExitCode = timedOut ? -1 : process.ExitCode,
            StandardOutput = stdout.ToString(),
            StandardError = stderr.ToString(),
            Duration = sw.Elapsed,
            TimedOut = timedOut,
        };
    }

    /// <summary>执行 PowerShell 官方模块命令（设计文档 4.1 推荐路径）。</summary>
    public static Task<ProcessRunResult> RunPowerShellAsync(
        string script, TimeSpan timeout, CancellationToken ct = default) =>
        RunAsync(WindowsPowerShellPath,
        [
            "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            // Windows PowerShell 默认按系统 OEM 代码页（如 936/949）输出，而读取端按 UTF-8 解码，
            // 中文接口名/路由别名会乱码：先把控制台输出编码切到 UTF-8
            "-Command", "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + script,
        ], timeout, ct);

    private static async Task PumpAsync(
        StreamReader reader, StringBuilder sink, int maxBytes)
    {
        var buffer = new char[4096];
        int total = 0;
        while (await reader.ReadAsync(buffer).ConfigureAwait(false) is { } n and > 0)
        {
            total += n;
            if (total <= maxBytes)
                sink.Append(buffer, 0, n);
            else
                sink.Append("…[输出超出上限已截断]");
        }
    }
}
