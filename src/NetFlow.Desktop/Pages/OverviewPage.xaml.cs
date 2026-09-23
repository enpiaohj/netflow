using System.Collections.ObjectModel;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NetFlow.Application;
using NetFlow.Desktop.Services;
using NetFlow.Windows;

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
            if (TargetInput.Text.Length == 0)
                TargetInput.Text = "输入 IP、域名或服务器名称";
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
            });
        }
        AdapterPanel.Children.Add(new TextBlock
        {
            Text = NetworkProfileCollector.GetProxyStatus(),
            Margin = new Thickness(0, 6, 0, 0),
            FontSize = 12,
            Foreground = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString("#64748B")),
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
        if (e.Key == Key.Enter && TargetInput.Text is { Length: > 0 } t && t != "输入 IP、域名或服务器名称")
            QuickTest_Click(sender, e);
    }

    private void QuickTest_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        if (target.Length == 0) return;
        NavigationState.PendingQuickTestTarget = IPAddress.TryParse(target, out _)
            ? target : target;
        NavigationState.Raise("quicktest");
    }

    private void Scenario_Click(object sender, RoutedEventArgs e) =>
        NavigationState.Raise("scenario");

    private void QuickNav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string } b)
            NavigationState.Raise(b.Tag.ToString()!);
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

    public static void Raise(string key) => RequestNavigation?.Invoke(key);
}
