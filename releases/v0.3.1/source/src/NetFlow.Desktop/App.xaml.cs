using System.Windows;
using NetFlow.Capture;

namespace NetFlow.Desktop;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        // 提权采集宿主模式：由主程序经 UAC 以本 exe 重新启动，只做采集，不创建任何窗口，
        // 也不初始化应用服务（数据库等）
        if (e.Args.Contains(PktmonCaptureController.SelfHostSwitch))
        {
            var exitCode = Task.Run(() => CaptureHostProgram.RunAsync(e.Args, CancellationToken.None))
                .GetAwaiter().GetResult();
            Environment.Exit(exitCode);
            return;
        }

        base.OnStartup(e);

        // 遗留抓包会话检测（设计文档 4.5：启动时检测并提示清理）
        var leftovers = PktmonCaptureController
            .DetectLeftoverSessionsAsync(Services.AppServices.Instance.EvidenceRoot, CancellationToken.None)
            .GetAwaiter().GetResult();
        if (leftovers.Count > 0)
        {
            MessageBox.Show(
                $"检测到 {leftovers.Count} 个未正常结束的抓包任务。\n" +
                "这些任务可能已被系统终止，可在“历史报告”中查看。",
                "NetFlow", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        new MainWindow().Show();
    }
}
