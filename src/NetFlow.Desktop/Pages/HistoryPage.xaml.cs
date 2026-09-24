using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetFlow.Application;
using NetFlow.Desktop.Services;

using NetFlow.Domain;

namespace NetFlow.Desktop.Pages;

public partial class HistoryPage : UserControl
{
    public ObservableCollection<HistoryRow> Rows { get; } = [];

    /// <summary>全量缓存，供搜索框实时过滤。</summary>
    private List<HistoryRow> _all = [];

    public HistoryPage()
    {
        InitializeComponent();
        HistoryGrid.ItemsSource = Rows;
        Loaded += async (_, _) => await LoadAsync().ConfigureAwait(true);
    }

    private async Task LoadAsync()
    {
        var services = AppServices.Instance;
        if (!services.PersistenceReady || services.Repository is null) return;
        try
        {
            var runs = await services.Repository.ListRunsAsync(300).ConfigureAwait(true);
            _all = runs.Select(r => new HistoryRow
            {
                StartLocal = r.Start?.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss") ?? "—",
                Target = r.Target,
                ScenarioName = r.ScenarioName ?? "自由测试",
                Id = r.Id,
                ScenarioId = r.ScenarioId,
            }).ToList();
            ApplyFilter();
        }
        catch (Exception ex)
        {
            AppLog.Warn($"历史记录加载失败：{ex.Message}");
        }
    }

    /// <summary>搜索框按目标/场景/任务 ID 过滤（设计文档 06 页：搜索、复查、重跑、导出）。</summary>
    private void ApplyFilter()
    {
        var keyword = SearchInput.Text.Trim();
        Rows.Clear();
        IEnumerable<HistoryRow> matched = _all;
        if (keyword.Length > 0)
        {
            matched = _all.Where(r =>
                r.Target.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.ScenarioName.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                r.Id.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }
        foreach (var row in matched)
            Rows.Add(row);
    }

    private void Search_KeyUp(object sender, KeyEventArgs e) => ApplyFilter();

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await LoadAsync().ConfigureAwait(true);

    /// <summary>双击数据行 = 打开报告（最常用操作）；双击表头/空白区不触发。</summary>
    private void HistoryGrid_DoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject src &&
            ItemsControl.ContainerFromElement(HistoryGrid, src) is DataGridRow)
        {
            OpenReport_Click(sender, e);
        }
    }

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

    private void Rerun_Click(object sender, RoutedEventArgs e)
    {
        if (HistoryGrid.SelectedItem is not HistoryRow row)
        {
            MessageBox.Show("请先选择一条记录", "NetFlow");
            return;
        }
        if (string.IsNullOrEmpty(row.ScenarioId))
        {
            MessageBox.Show("该记录为自由测试，未关联场景模板，暂不支持重跑。", "NetFlow");
            return;
        }
        NavigationState.PendingScenarioRun = (row.ScenarioId, row.Target);
        NavigationState.Raise("scenario");
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
    public string? ScenarioId { get; init; }
}
