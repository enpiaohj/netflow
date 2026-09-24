using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Desktop.Services;
using NetFlow.Windows;

namespace NetFlow.Desktop.Pages;

public partial class ServicesPage : UserControl
{
    public ObservableCollection<ServiceRow> Services { get; } = [];
    public ObservableCollection<EventRow> Events { get; } = [];
    public ObservableCollection<SocketEndpointInfo> Listeners { get; } = [];

    public ServicesPage()
    {
        InitializeComponent();
        ServiceGrid.ItemsSource = Services;
        EventGrid.ItemsSource = Events;
        ListenerGrid.ItemsSource = Listeners;
        Loaded += async (_, _) =>
        {
            TargetInput.Text = Environment.MachineName;
            await LoadListenersAsync().ConfigureAwait(true);
        };
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        var isLocal = target.Length == 0 ||
            string.Equals(target, Environment.MachineName, StringComparison.OrdinalIgnoreCase);

        Services.Clear();
        try
        {
            var services = await Task.Run(() => WindowsServiceReader.GetServices(
                isLocal ? null : target)).ConfigureAwait(true);
            foreach (var s in services.Take(200))
            {
                Services.Add(new ServiceRow
                {
                    ServiceName = s.ServiceName,
                    DisplayName = s.DisplayName,
                    Status = s.Status,
                    StartType = s.StartType,
                });
            }
            AppServices.Instance.PublishStatus($"服务查询：{services.Count} 项");
        }
        catch (Exception ex)
        {
            // 无权限/不可达：明确提示，保留可移交的错误证据
            MessageBox.Show(
                $"远端服务查询失败：{ex.Message}\n\n网络侧检查仍可正常使用；服务状态记为“未检查”。",
                "NetFlow", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        if (EventGrid.Items.Count == 0)
            await LoadEventsAsync(isLocal, target).ConfigureAwait(true);
    }

    private async void Events_Click(object sender, RoutedEventArgs e) =>
        await LoadEventsAsync(
            string.Equals(TargetInput.Text.Trim(), Environment.MachineName, StringComparison.OrdinalIgnoreCase)
            || TargetInput.Text.Trim().Length == 0,
            TargetInput.Text.Trim()).ConfigureAwait(true);

    private async Task LoadEventsAsync(bool isLocal, string target)
    {
        Events.Clear();
        try
        {
            int count = int.TryParse(EventCountInput.Text, out var c) ? c : 20;
            var entries = await Task.Run(() => WindowsServiceReader.GetRecentEvents(
                LogNameInput.Text, count, isLocal ? null : target)).ConfigureAwait(true);
            foreach (var e in entries)
            {
                Events.Add(new EventRow
                {
                    TimeLocal = e.TimeCreated.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
                    Level = e.Level,
                    EventId = e.EventId,
                    Provider = e.Provider,
                    Message = e.Message.Length > 160 ? e.Message[..160] + "…" : e.Message,
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"事件日志查询失败：{ex.Message}", "NetFlow",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async Task LoadListenersAsync()
    {
        try
        {
            var endpoints = await Task.Run(() => TcpTableReader.GetTcpEndpoints()).ConfigureAwait(true);
            foreach (var ep in endpoints.Where(e => e.State == "LISTENING").Take(300))
                Listeners.Add(ep);
        }
        catch (Exception ex)
        {
            AppServices.Instance.PublishStatus($"监听端口读取失败：{ex.Message}");
        }
    }
}

public record ServiceRow
{
    public required string ServiceName { get; init; }
    public required string DisplayName { get; init; }
    public required string Status { get; init; }
    public required string StartType { get; init; }
}

public record EventRow
{
    public required string TimeLocal { get; init; }
    public required string Level { get; init; }
    public required int EventId { get; init; }
    public required string Provider { get; init; }
    public required string Message { get; init; }
}
