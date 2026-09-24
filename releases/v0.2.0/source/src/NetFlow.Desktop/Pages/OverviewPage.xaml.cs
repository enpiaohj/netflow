using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetFlow.Application;
using NetFlow.Desktop.Services;
using NetFlow.Windows;

using NetFlow.Domain;

namespace NetFlow.Desktop.Pages;

public partial class OverviewPage : UserControl
{
    public ObservableCollection<RecentRunRow> Recent { get; } = [];

    public OverviewPage()
    {
        InitializeComponent();
        RecentGrid.ItemsSource = Recent;
        Loaded += async (_, _) =>
        {
            try
            {
                await LoadAdaptersAsync().ConfigureAwait(true);
                await LoadRecentAsync().ConfigureAwait(true);
            }
            catch (Exception ex)
            {
                AppLog.Warn($"总览页数据加载失败：{ex.Message}");
            }
        };
    }

    private async Task LoadAdaptersAsync()
    {
        AdapterPanel.Children.Clear();
        var adapters = await Task.Run(() => NetworkProfileCollector.CollectAdapters()).ConfigureAwait(true);
        foreach (var a in adapters.Where(a => !a.IsLoopback).Take(4))
        {
            AdapterPanel.Children.Add(new TextBlock
            {
                Text = $"{a.Name}｜{string.Join(", ", a.Ipv4Addresses)}｜网关 {a.Gateways.FirstOrDefault() ?? "—"}",
                Margin = new Thickness(0, 3, 0, 3),
                FontSize = 13,
                TextWrapping = TextWrapping.Wrap,
            });
        }
        AdapterPanel.Children.Add(new TextBlock
        {
            Text = NetworkProfileCollector.GetProxyStatus(),
            Margin = new Thickness(0, 6, 0, 0),
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Foreground = (System.Windows.Media.Brush)FindResource("TextSecondary"),
        });
    }

    private async Task LoadRecentAsync()
    {
        Recent.Clear();
        var services = AppServices.Instance;
        if (!services.PersistenceReady || services.Repository is null) return;
        var runs = await services.Repository
            .ListRunsAsync(20).ConfigureAwait(true);
        foreach (var r in runs)
        {
            Recent.Add(new RecentRunRow
            {
                StartLocal = r.Start?.LocalDateTime.ToString("yyyy-MM-dd HH:mm") ?? "—",
                Target = r.Target,
                ScenarioName = r.ScenarioName ?? "自由测试",
            });
        }
    }

    private void TargetInput_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            QuickTest_Click(sender, e);
        }
    }

    private void QuickTest_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        if (target.Length == 0)
        {
            TargetInput.Focus();
            return;
        }
        NavigationState.PendingQuickTestTarget = target;
        NavigationState.Raise("quicktest");
    }

    private void Scenario_Click(object sender, RoutedEventArgs e) =>
        NavigationState.Raise("scenario");

    /// <summary>快速入口：Tag 形如 "页面" 或 "页面:子类型"（如 quicktest:dns 直接切到 DNS 测试）。</summary>
    private void QuickNav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string tag }) return;
        var parts = tag.Split(':', 2);
        if (parts.Length == 2 && parts[0] == "quicktest")
            NavigationState.PendingQuickTestTab = parts[1];
        NavigationState.Raise(parts[0]);
    }
}

public record RecentRunRow
{
    public required string StartLocal { get; init; }
    public required string Target { get; init; }
    public required string ScenarioName { get; init; }
}

/// <summary>跨页面导航请求（由 MainWindow 订阅）。</summary>
public static class NavigationState
{
    public static event Action<string>? RequestNavigation;
    public static string? PendingQuickTestTarget { get; set; }

    /// <summary>快速测试页待选中的测试类型（tcpudp / dns / http / ping / ntp）。</summary>
    public static string? PendingQuickTestTab { get; set; }

    /// <summary>历史页"重跑"请求（场景模板 ID + 目标）。</summary>
    public static (string ScenarioId, string Target)? PendingScenarioRun { get; set; }

    public static void Raise(string key) => RequestNavigation?.Invoke(key);
}
