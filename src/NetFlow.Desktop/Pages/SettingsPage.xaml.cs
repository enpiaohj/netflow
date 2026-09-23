using System.Windows;
using System.Windows.Controls;
using NetFlow.Capture;
using NetFlow.Desktop.Services;
using NetFlow.Application;
using NetFlow.Windows;

namespace NetFlow.Desktop.Pages;

public partial class SettingsPage : UserControl
{
    public SettingsPage()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            ElevatedText.Text = NetworkInterfaceHelper.IsElevated()
                ? "当前已获取管理员权限：pktmon 抓包可直接使用。"
                : "当前为普通权限：抓包开始时会通过 UAC 请求一次提升；拒绝后仅执行普通探针。";
            StorageText.Text =
                $"数据库：{AppServices.Instance.DatabasePath}\n" +
                $"证据目录：{AppServices.Instance.EvidenceRoot}\n" +
                "留存策略：默认 30 天（可在后续版本配置自动清理）。";
            await DetectPktmonAsync().ConfigureAwait(true);
            await DetectTsharkAsync().ConfigureAwait(true);
        };
    }

    private async Task DetectPktmonAsync()
    {
        PktmonText.Text = "检测中…";
        var cap = await PktmonCaptureController.DetectCapabilityAsync(CancellationToken.None)
            .ConfigureAwait(true);
        PktmonText.Text = cap.Available
            ? $"已检测到 Windows Pktmon（{cap.Version}）。抓包引擎：Windows Pktmon（推荐）。"
            : $"Pktmon 不可用：{cap.Error}。系统将降级为纯网络测试与导入分析，不虚构抓包能力。";
    }

    private async Task DetectTsharkAsync()
    {
        TsharkText.Text = "TShark 检测中…";
        var cap = await TsharkAdapter.DetectAsync(CancellationToken.None).ConfigureAwait(true);
        TsharkText.Text = cap.Available
            ? $"TShark：{cap.Version}（{cap.Path}）。用于深层离线解析，不作为默认抓包后端，不捆绑分发。"
            : $"TShark：未检测到（可选组件）。{cap.Error}";
    }

    private async void Detect_Click(object sender, RoutedEventArgs e) =>
        await DetectPktmonAsync().ConfigureAwait(true);

    private async void DetectTshark_Click(object sender, RoutedEventArgs e) =>
        await DetectTsharkAsync().ConfigureAwait(true);
}
