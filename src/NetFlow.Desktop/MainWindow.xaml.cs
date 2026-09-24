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
        // 默认尺寸偏大以容纳三栏页面；小屏时收缩到工作区内
        var work = SystemParameters.WorkArea;
        Width = Math.Min(Width, work.Width);
        Height = Math.Min(Height, work.Height);
        VersionText.Text = $"v{NetFlowInfo.Version}";
        ElevatedText.Text = NetworkInterfaceHelper.IsElevated()
            ? "已使用管理员权限"
            : "标准权限：抓包时将请求管理员权限";
        RefreshSourceChoices();
        // 网卡可能在使用期间上线/下线/换 IP：窗口重新获得焦点时刷新候选
        Activated += (_, _) => RefreshSourceChoices();
        SourceSelection.ResetRequested += () => Dispatcher.BeginInvoke(() =>
        {
            SourceSelection.SelectedAdapterName = null;
            UiState.SourceAdapterName = null;
            RefreshSourceChoices();
        });

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
            var options = SourceAdapterCatalog.List();
            var choices = options.Select(o => new SourceChoice(o.Display, o.Name)).ToList();
            SourceAdapterCombo.ItemsSource = choices;

            // 测试必须明确源网络：没有“自动”。优先沿用当前/上次的选择，
            // 不可用则取默认（带默认网关的以太网卡）
            var wanted = SourceSelection.SelectedAdapterName ?? UiState.SourceAdapterName;
            var current = wanted is null ? null : choices.FirstOrDefault(c => c.AdapterName == wanted);
            if (current is null)
            {
                var fallback = SourceAdapterCatalog.PickDefault(options);
                current = fallback is null ? null : choices.First(c => c.AdapterName == fallback.Name);
                if (wanted is not null && current is not null)
                    AppServices.Instance.PublishStatus(
                        $"源网卡“{wanted}”已断开，已切换为 {current.Display}。");
            }
            SourceSelection.SelectedAdapterName = current?.AdapterName;
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
        UiState.SourceAdapterName = choice.AdapterName;
        AppServices.Instance.PublishStatus($"源网卡已切换为：{choice.Display}");
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
