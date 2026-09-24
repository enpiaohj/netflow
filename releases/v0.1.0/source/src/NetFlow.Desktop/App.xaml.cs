using System.Windows;

namespace NetFlow.Desktop;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // 遗留抓包会话检测（设计文档 4.5：启动时检测并提示清理）
        var leftovers = NetFlow.Capture.PktmonCaptureController
            .DetectLeftoverSessionsAsync(Services.AppServices.Instance.EvidenceRoot, CancellationToken.None)
            .GetAwaiter().GetResult();
        if (leftovers.Count > 0)
        {
            MessageBox.Show(
                $"检测到 {leftovers.Count} 个未正常结束的抓包任务目录。\n" +
                "相关采集会话可能已随系统清理；可在历史任务中检查对应任务状态。",
                "NetFlow", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
