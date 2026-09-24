namespace NetFlow.CaptureHost;

/// <summary>
/// 提权采集宿主入口。用法：NetFlow.CaptureHost --params &lt;参数文件路径&gt;
/// 该进程由主程序以管理员身份一次性启动（UAC），完成采集后退出。
/// </summary>
public static class Program
{
    [STAThread]
    public static async Task<int> Main(string[] args)
    {
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        return await CaptureHostProgram.RunAsync(args, cts.Token).ConfigureAwait(false);
    }
}
