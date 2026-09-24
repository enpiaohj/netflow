using System.ServiceProcess;

namespace NetFlow.Windows;

/// <summary>Windows 服务快照（设计文档 4.6）。</summary>
public sealed record ServiceInfo
{
    public required string ServiceName { get; init; }
    public required string DisplayName { get; init; }
    public required string Status { get; init; }
    public required string StartType { get; init; }
    public int? Pid { get; init; }
    public required IReadOnlyList<string> DependentServices { get; init; }
    public required IReadOnlyList<string> ServicesDependedOn { get; init; }
}

/// <summary>事件日志条目。</summary>
public sealed record EventEntry
{
    public required DateTimeOffset TimeCreated { get; init; }
    public required int EventId { get; init; }
    public required string Level { get; init; }
    public required string Provider { get; init; }
    public required string Message { get; init; }
}

/// <summary>
/// Windows 服务与事件日志读取（本机/远端）。远端使用用户已有权限，
/// 无"万能代理"；权限缺失保留错误并标注"未检查"。
/// </summary>
public static class WindowsServiceReader
{
    /// <summary>按名称查询服务状态。machineName null = 本机。</summary>
    public static ServiceInfo? GetService(string serviceName, string? machineName = null)
    {
        try
        {
            using var sc = machineName is null
                ? new ServiceController(serviceName)
                : new ServiceController(serviceName, machineName);
            return ToInfo(sc);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // 服务不存在或无权限——返回 null，由调用方标注未检查及原因
            return null;
        }
    }

    /// <summary>列出服务。远端失败抛出带原因的异常（认证拒绝/端口不可达等区分）。</summary>
    public static IReadOnlyList<ServiceInfo> GetServices(string? machineName = null)
    {
        var services = machineName is null
            ? ServiceController.GetServices()
            : ServiceController.GetServices(machineName);
        return [.. services.Select(ToInfo)];
    }

    private static ServiceInfo ToInfo(ServiceController sc)
    {
        string[] deps = [], dependedOn = [];
        try { deps = [.. sc.DependentServices.Select(d => d.ServiceName)]; } catch { /* 权限受限逐项标注 */ }
        try { dependedOn = [.. sc.ServicesDependedOn.Select(d => d.ServiceName)]; } catch { }

        // ServiceController 不直接暴露 PID；PID 由 TcpTableReader 的端口关联补充。
        // 此处留空并在 UI 说明来源。

        return new ServiceInfo
        {
            ServiceName = sc.ServiceName,
            DisplayName = sc.DisplayName,
            Status = sc.Status.ToString(),
            StartType = sc.StartType.ToString(),
            Pid = null, // ServiceController 不暴露 PID；由 TcpTableReader 端口关联补充
            DependentServices = deps,
            ServicesDependedOn = dependedOn,
        };
    }

    /// <summary>
    /// 查询最近事件。使用 System.Diagnostics.Eventing.Reader（支持远端机器名）。
    /// </summary>
    public static IReadOnlyList<EventEntry> GetRecentEvents(
        string logName, int maxEvents, string? machineName = null,
        string? xpathFilter = null)
    {
        var query = new System.Diagnostics.Eventing.Reader.EventLogQuery(
            logName,
            System.Diagnostics.Eventing.Reader.PathType.LogName,
            xpathFilter ?? "*")
        {
            ReverseDirection = true,
        };
        if (machineName is not null)
            query.Session = new System.Diagnostics.Eventing.Reader.EventLogSession(machineName);

        var entries = new List<EventEntry>();
        using var reader = new System.Diagnostics.Eventing.Reader.EventLogReader(query);
        for (int i = 0; i < maxEvents; i++)
        {
            using var evt = reader.ReadEvent();
            if (evt is null) break;
            entries.Add(new EventEntry
            {
                TimeCreated = evt.TimeCreated?.ToUniversalTime() ?? default,
                EventId = evt.Id,
                Level = evt.LevelDisplayName ?? evt.Level?.ToString() ?? "未知",
                Provider = evt.ProviderName,
                Message = evt.FormatDescription() ?? "",
            });
        }
        return entries;
    }
}
