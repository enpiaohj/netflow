using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Application;
using NetFlow.Desktop.Services;
using System.IO;

namespace NetFlow.Desktop.Pages;

public partial class HistoryPage : UserControl
{
    public ObservableCollection<HistoryRow> Rows { get; } = [];

    public HistoryPage()
    {
        InitializeComponent();
        HistoryGrid.ItemsSource = Rows;
        Loaded += async (_, _) => await LoadAsync().ConfigureAwait(true);
    }

    private async Task LoadAsync()
    {
        Rows.Clear();
        var services = AppServices.Instance;
        if (!services.PersistenceReady || services.Repository is null) return;
        try
        {
            var runs = await services.Repository.ListRunsAsync(300).ConfigureAwait(true);
            foreach (var r in runs)
            {
                Rows.Add(new HistoryRow
                {
                    StartLocal = r.Start?.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "—",
                    Target = r.Target,
                    ScenarioName = r.ScenarioName ?? "自由测试",
                    Id = r.Id,
                });
            }
        }
        catch (Exception ex)
        {
            AppLog.Warn($"历史记录加载失败：{ex.Message}");
        }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync().ConfigureAwait(true);

    private void OpenReport_Click(object sender, RoutedEventArgs e)
    {
        if (HistoryGrid.SelectedItem is not HistoryRow row)
        {
            MessageBox.Show("请先选择一条记录", "NetFlow");
            return;
        }
        var reportPath = Path.Combine(
            AppServices.Instance.EvidenceRoot, row.Id, "report.html");
        if (!File.Exists(reportPath))
        {
            // 原始文件可能已按留存策略清理——如实提示，不留失效入口
            MessageBox.Show(
                "报告文件已清理或尚未生成（留存策略可能已删除原始文件）。\n" +
                $"期望位置：{reportPath}", "NetFlow",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = reportPath,
            UseShellExecute = true,
        });
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = AppServices.Instance.EvidenceRoot,
            UseShellExecute = true,
        });
    }
}

public record HistoryRow
{
    public required string StartLocal { get; init; }
    public required string Target { get; init; }
    public required string ScenarioName { get; init; }
    public required string Id { get; init; }
}
