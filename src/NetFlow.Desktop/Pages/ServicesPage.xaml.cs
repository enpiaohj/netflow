using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Desktop.Services;
using NetFlow.Domain;
using NetFlow.Probes;
using NetFlow.Windows;

namespace NetFlow.Desktop.Pages;

public partial class ServicesPage : UserControl
{
    public ObservableCollection<ServiceRow> Services { get; } = [];
    public ObservableCollection<EventRow> Events { get; } = [];
    public ObservableCollection<SocketEndpointInfo> Listeners { get; } = [];

    private static readonly (string Text, EventLevelFilter Level)[] LevelChoices =
    [
        ("全部级别", EventLevelFilter.All),
        ("严重", EventLevelFilter.Critical),
        ("错误", EventLevelFilter.Error),
        ("警告", EventLevelFilter.Warning),
        ("信息", EventLevelFilter.Information),
        ("详细", EventLevelFilter.Verbose),
        ("错误及以上（严重 + 错误）", EventLevelFilter.ErrorAndAbove),
        ("警告及以上（严重 + 错误 + 警告）", EventLevelFilter.WarningAndAbove),
    ];

    private static readonly (string Text, TimeSpan? Span)[] TimeChoices =
    [
        ("不限时间", null),
        ("最近 1 小时", TimeSpan.FromHours(1)),
        ("最近 24 小时", TimeSpan.FromHours(24)),
        ("最近 7 天", TimeSpan.FromDays(7)),
        ("最近 30 天", TimeSpan.FromDays(30)),
    ];

    public ServicesPage()
    {
        InitializeComponent();
        ServiceGrid.ItemsSource = Services;
        EventGrid.ItemsSource = Events;
        ListenerGrid.ItemsSource = Listeners;
        UiState.Bind(TargetInput, "server");
        InitEventFilters();

        // 目标留空 = 本机；输入变化后刷新“需要开放哪些端口”的提示
        TargetInput.LostKeyboardFocus += (_, _) => UpdateRemoteHint();
        TargetInput.DropDownClosed += (_, _) => UpdateRemoteHint();
        UpdateRemoteHint();

        Loaded += async (_, _) => await LoadListenersAsync().ConfigureAwait(true);
    }

    /// <summary>事件日志筛选项：日志名、级别、时间范围、事件 ID、条数，全部预置，默认查“安全”日志。</summary>
    private void InitEventFilters()
    {
        foreach (var preset in EventFilterBuilder.LogPresets) LogNameInput.Items.Add(preset.Display);
        LogNameInput.Text = EventFilterBuilder.LogPresets[0].Display;

        foreach (var (text, _) in LevelChoices) LevelInput.Items.Add(text);
        LevelInput.SelectedIndex = 0;

        foreach (var (text, _) in TimeChoices) TimeInput.Items.Add(text);
        TimeInput.SelectedIndex = 0;

        foreach (var preset in EventFilterBuilder.IdPresets) EventIdInput.Items.Add(preset.Display);

        foreach (var count in new[] { "20", "50", "100", "200", "500" }) EventCountInput.Items.Add(count);
        EventCountInput.Text = "20";
    }

    private static bool IsLocal(string target) =>
        target.Length == 0 || string.Equals(target, Environment.MachineName, StringComparison.OrdinalIgnoreCase)
        || target is "localhost" or "127.0.0.1" or ".";

    /// <summary>远程查询需要的端口提示；本机无需端口。</summary>
    private void UpdateRemoteHint()
    {
        var target = TargetInput.Text.Trim();
        RemoteHint.Text = IsLocal(target)
            ? "本机查询无需开放端口；读取 Security 日志需管理员权限。"
            : "远程查询需目标放行 TCP 135（RPC 端点映射）及动态 RPC 端口 49152–65535" +
              "（防火墙规则组“远程事件日志管理”“WMI”）；服务列表另需 TCP 445。需使用具备权限的账户。";
    }

    private async void PortCheck_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        PortCheckText.Text = "";
        if (IsLocal(target))
        {
            PortCheckText.Text = "目标为本机，无需检测远程端口。";
            return;
        }
        UiState.Remember(TargetInput, "server");

        IPAddress ip;
        try
        {
            ip = IPAddress.TryParse(target, out var direct)
                ? direct
                : (await Dns.GetHostAddressesAsync(target).ConfigureAwait(true)).First();
        }
        catch (Exception ex)
        {
            PortCheckText.Text = $"无法解析主机名：{ex.Message}";
            return;
        }

        var (source, sourceError) = SourceSelection.Resolve(ip.AddressFamily);
        if (sourceError is not null)
        {
            PortCheckText.Text = sourceError;
            return;
        }

        PortCheckText.Text = "正在检测…";
        var checks = new[] { (Port: 135, Name: "RPC 端点映射"), (Port: 445, Name: "SMB") };
        var results = await Task.WhenAll(checks.Select(async c =>
        {
            var run = await new TcpConnectProbe().ExecuteAsync(ip, c.Port, new ProbeRequest
            {
                RunId = RunId.New(),
                SourceAddress = source,
                Parameters = new ProbeParameters
                {
                    ProbeType = ProbeType.TcpConnect, RequestedTarget = target, Port = c.Port,
                    Timeout = TimeSpan.FromSeconds(3),
                },
            }).ConfigureAwait(false);
            return (c.Port, c.Name, Ok: run.Transport == TransportOutcome.Success,
                Text: UiText.Transport(run.Transport));
        })).ConfigureAwait(true);

        var line = string.Join("　", results.Select(r => $"TCP {r.Port}（{r.Name}）：{(r.Ok ? "可连接" : r.Text)}"));
        var rpc = results[0].Ok;
        PortCheckText.Text = line + (rpc
            ? "。动态 RPC 端口（49152–65535）无法在此验证，查询仍失败时请检查目标防火墙。"
            : "。TCP 135 不可达，远程事件日志与服务查询将失败，请放行 TCP 135 及动态 RPC 端口。");
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        if (target.Length > 0) UiState.Remember(TargetInput, "server");
        UpdateRemoteHint();
        var isLocal = IsLocal(target);

        ServiceHint.Text = "";
        Services.Clear();
        try
        {
            var services = await Task.Run(() => WindowsServiceReader.GetServices(
                isLocal ? null : target)).ConfigureAwait(true);
            foreach (var s in services.Take(500))
            {
                Services.Add(new ServiceRow
                {
                    ServiceName = s.ServiceName,
                    DisplayName = s.DisplayName,
                    Status = ServiceStatusText(s.Status),
                    StartType = StartTypeText(s.StartType),
                });
            }
            AppServices.Instance.PublishStatus($"服务查询：{services.Count} 项");
        }
        catch (Exception ex)
        {
            // 无权限/不可达：明确提示（页面内），服务状态记为“未检查”
            ServiceHint.Text = $"无法查询服务：{ex.Message}。服务状态记为“未检查”，其他检测不受影响。";
        }
    }

    private static string ServiceStatusText(string status) => status switch
    {
        "Running" => "正在运行",
        "Stopped" => "已停止",
        "Paused" => "已暂停",
        "StartPending" => "正在启动",
        "StopPending" => "正在停止",
        "ContinuePending" => "正在继续",
        "PausePending" => "正在暂停",
        _ => status,
    };

    private static string StartTypeText(string startType) => startType switch
    {
        "Automatic" => "自动",
        "Manual" => "手动",
        "Disabled" => "已禁用",
        "Boot" => "引导",
        "System" => "系统",
        _ => startType,
    };

    private async void Events_Click(object sender, RoutedEventArgs e)
    {
        var target = TargetInput.Text.Trim();
        UpdateRemoteHint();
        await LoadEventsAsync(IsLocal(target), target).ConfigureAwait(true);
    }

    private async Task LoadEventsAsync(bool isLocal, string target)
    {
        Events.Clear();
        EventHint.Text = "";

        var logName = EventFilterBuilder.ParseLogName(LogNameInput.Text);
        if (logName.Length == 0)
        {
            EventHint.Text = "请选择或输入日志名称。";
            LogNameInput.Focus();
            return;
        }

        var ids = EventFilterBuilder.ParseIds(EventIdInput.Text, out var idErrors);
        if (idErrors.Count > 0)
        {
            EventHint.Text = string.Join("；", idErrors);
            EventIdInput.Focus();
            return;
        }

        var level = LevelChoices[Math.Max(0, LevelInput.SelectedIndex)].Level;
        var within = TimeChoices[Math.Max(0, TimeInput.SelectedIndex)].Span;
        var xpath = EventFilterBuilder.BuildXPath(ids, level, within);

        try
        {
            int count = int.TryParse(EventCountInput.Text, out var c) ? Math.Clamp(c, 1, 2000) : 20;
            var entries = await Task.Run(() => WindowsServiceReader.GetRecentEvents(
                logName, count, isLocal ? null : target, xpath)).ConfigureAwait(true);
            foreach (var ev in entries)
            {
                Events.Add(new EventRow
                {
                    TimeLocal = ev.TimeCreated.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss"),
                    Level = ev.Level,
                    EventId = ev.EventId,
                    Provider = ev.Provider,
                    Message = OneLine(ev.Message),
                });
            }
            if (entries.Count == 0)
                EventHint.Text = $"日志“{logName}”中没有符合条件的事件";
        }
        catch (UnauthorizedAccessException)
        {
            EventHint.Text = $"无权读取“{logName}”日志。请以管理员身份运行，或将当前账户加入 Event Log Readers 组" +
                (isLocal ? "。" : "（远程查询使用当前 Windows 身份）。");
        }
        catch (EventLogNotFoundException)
        {
            EventHint.Text = $"找不到日志“{logName}”。请从列表中选择，或检查日志名称" +
                (isLocal ? "。" : "；远程查询还需确认目标上存在该日志、且 RPC（135 + 动态端口）可达。");
        }
        catch (EventLogException ex)
        {
            EventHint.Text = isLocal
                ? $"无法查询事件日志：{ex.Message}"
                : $"无法查询远程事件日志：{ex.Message}。请确认目标已放行 TCP 135 及动态 RPC 端口（可使用“检测远程端口”），且账户具有权限。";
        }
        catch (Exception ex)
        {
            EventHint.Text = $"无法查询事件日志：{ex.Message}";
        }
    }

    /// <summary>事件消息常含换行，表格中压成单行并截断。</summary>
    private static string OneLine(string message)
    {
        var text = message.Replace("\r", " ").Replace("\n", " ").Trim();
        return text.Length > 200 ? text[..200] + "…" : text;
    }

    private async Task LoadListenersAsync()
    {
        try
        {
            var endpoints = await Task.Run(() => TcpTableReader.GetTcpEndpoints()).ConfigureAwait(true);
            Listeners.Clear();
            foreach (var ep in endpoints.Where(e => e.State == "LISTENING").Take(300))
                Listeners.Add(ep);
        }
        catch (Exception ex)
        {
            AppServices.Instance.PublishStatus($"无法读取监听端口：{ex.Message}");
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
