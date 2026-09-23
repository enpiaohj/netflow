using System.Windows;
using System.Windows.Controls;
using NetFlow.Desktop.Pages;
using NetFlow.Desktop.Services;

namespace NetFlow.Desktop;

public partial class MainWindow : Window
{
    private readonly Dictionary<string, Func<UserControl>> _pages;

    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = $"v{NetFlow.Domain.NetFlowInfo.Version}";
        ElevatedText.Text = AppServices.Instance.Orchestrator == null ? "" :
            (NetFlow.Application.NetworkInterfaceHelper.IsElevated()
                ? "管理员权限：可用（抓包可用）"
                : "普通权限：抓包将通过 UAC 按需提升");

        AppServices.Instance.StatusMessage += (_, msg) => Dispatcher.BeginInvoke(() =>
            StatusText.Text = msg);

        _pages = new Dictionary<string, Func<UserControl>>
        {
            ["overview"] = () => new OverviewPage(),
            ["quicktest"] = () => new QuickTestPage(),
            ["scenario"] = () => new ScenarioPage(),
            ["capture"] = () => new CapturePage(),
            ["services"] = () => new ServicesPage(),
            ["localnet"] = () => new LocalNetworkPage(),
            ["batch"] = () => new BatchPage(),
            ["history"] = () => new HistoryPage(),
            ["settings"] = () => new SettingsPage(),
        };

        NavOverview.IsChecked = true;
        ShowPage("overview");

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
        if (_pages.TryGetValue(key, out var factory))
            PageHost.Content = factory();
    }
}
