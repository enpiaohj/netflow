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
