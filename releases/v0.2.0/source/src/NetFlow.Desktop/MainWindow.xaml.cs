using System.Windows;
using System.Windows.Controls;
using NetFlow.Application;
using NetFlow.Desktop.Pages;
using NetFlow.Desktop.Services;
using NetFlow.Domain;

namespace NetFlow.Desktop;

public partial class MainWindow : Window
{
    private readonly Dictionary<string, UserControl> _pages;

    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = $"v{NetFlowInfo.Version}";
        ElevatedText.Text = NetworkInterfaceHelper.IsElevated()
            ? "管理员权限：可用（抓包可用）"
            : "普通权限：抓包将通过 UAC 按需提升";
        RefreshSourceChoices();
        // 网卡可能在使用期间上线/下线/换 IP：窗口重新获得焦点时刷新候选
        Activated += (_, _) => RefreshSourceChoices();

        AppServices.Instance.StatusMessage += (_, msg) => Dispatcher.BeginInvoke(() =>
            StatusText.Text = msg);

        // 页面实例缓存：切换页面不重建、不丢失运行中任务与已加载结果（设计文档 3.1）
        _pages = new Dictionary<string, UserControl>
        {
            ["overview"] = new OverviewPage(),
            ["quicktest"] = new QuickTestPage(),
            ["scenario"] = new ScenarioPage(),
            ["capture"] = new CapturePage(),
            ["services"] = new ServicesPage(),
            ["localnet"] = new LocalNetworkPage(),
            ["batch"] = new BatchPage(),
            ["history"] = new HistoryPage(),
            ["settings"] = new SettingsPage(),
        };

        // 全局活动指示：任何页面有任务在跑时顶栏可见
        ActivityState.Changed += (_, _) => Dispatcher.BeginInvoke(RefreshActivity);

        NavigationState.RequestNavigation += key => Dispatcher.BeginInvoke(() =>
        {
            foreach (var rb in FindVisualChildren<RadioButton>(this))
            {
                if (rb.GroupName == "nav" && Equals(rb.Tag?.ToString(), key))
                {
                    rb.IsChecked = true;
                    return;
                }
            }
            ShowPage(key);
        });

        NavOverview.IsChecked = true;
        ShowPage("overview");
    }

    /// <summary>源网卡下拉项：AdapterName 为 null 表示“自动”。</summary>
    private sealed record SourceChoice(string Display, string? AdapterName)
    {
        // 自动化名称/读屏取 ToString：避免显示 record 默认的 “SourceChoice { … }”
        public override string ToString() => Display;
    }

    private bool _refreshingSources;

    private void RefreshSourceChoices()
    {
        _refreshingSources = true;
        try
        {
            var preferred = NetworkInterfaceHelper.GetPreferredAdapterName(null);
            var choices = new List<SourceChoice>
            {
                new(preferred is null
                    ? "自动（系统路由选择）"
                    : $"自动（系统路由选择，默认 {preferred}）", null),
            };
            choices.AddRange(SourceAdapterCatalog.List().Select(o => new SourceChoice(o.Display, o.Name)));
            SourceAdapterCombo.ItemsSource = choices;

            var selectedName = SourceSelection.SelectedAdapterName;
            var current = selectedName is null
                ? choices[0]
                : choices.FirstOrDefault(c => c.AdapterName == selectedName);
            if (current is null)
            {
                // 所选网卡已下线：回到自动并提示，避免仍按不存在的网卡执行
                SourceSelection.SelectedAdapterName = null;
                AppServices.Instance.PublishStatus($"源网卡“{selectedName}”已不在线，已恢复为“自动”");
                current = choices[0];
            }
            SourceAdapterCombo.SelectedItem = current;
        }
        catch (Exception ex)
        {
            AppLog.Warn($"源网卡列表读取失败：{ex.Message}");
        }
        finally
        {
            _refreshingSources = false;
        }
    }

    private void SourceAdapterCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshingSources || SourceAdapterCombo.SelectedItem is not SourceChoice choice) return;
        SourceSelection.SelectedAdapterName = choice.AdapterName;
        AppServices.Instance.PublishStatus(choice.AdapterName is null
            ? "测试源：自动（系统路由选择）"
            : $"测试源：{choice.Display}（各探针将绑定该网卡地址）");
    }

    private void RefreshActivity()
    {
        var activities = ActivityState.Current;
        if (activities.Count == 0)
        {
            ActivityButton.Visibility = Visibility.Collapsed;
            return;
        }
        ActivityButton.Visibility = Visibility.Visible;
        var names = string.Join("；", activities.Select(a => a.Label));
        ActivityText.Text = $"● 运行中：{names}";
        ActivityButton.Tag = activities[0].PageKey;
    }

    private void ActivityButton_Click(object sender, RoutedEventArgs e)
    {
        if (ActivityButton.Tag is string key)
        {
            foreach (var rb in FindVisualChildren<RadioButton>(this))
            {
                if (rb.GroupName == "nav" && Equals(rb.Tag?.ToString(), key))
                {
                    rb.IsChecked = true;
                    return;
                }
            }
        }
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject root)
        where T : DependencyObject
    {
        for (int i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(root, i);
            if (child is T typed) yield return typed;
            foreach (var sub in FindVisualChildren<T>(child))
                yield return sub;
        }
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is RadioButton { Tag: string key } && _pages is not null)
            ShowPage(key);
    }

    private void ShowPage(string key)
    {
        if (_pages.TryGetValue(key, out var page))
            PageHost.Content = page;
    }
}
