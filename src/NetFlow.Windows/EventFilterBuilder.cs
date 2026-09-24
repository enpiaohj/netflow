using System.Text;
using System.Text.RegularExpressions;

namespace NetFlow.Windows;

/// <summary>事件级别筛选（Windows 事件级别：1 严重、2 错误、3 警告、4 信息、5 详细；0 为“始终记录”，如安全审核事件）。</summary>
public enum EventLevelFilter
{
    All,
    Critical,
    Error,
    Warning,
    Information,
    Verbose,
    ErrorAndAbove,
    WarningAndAbove,
}

/// <summary>事件日志名预置（中文显示 + 实际日志名）。</summary>
public sealed record EventLogPreset(string Display, string LogName);

/// <summary>事件 ID 预置（Ids 为逗号分隔）。</summary>
public sealed record EventIdPreset(string Display, string Ids);

/// <summary>事件查询 XPath 构造与输入解析（纯函数，便于测试）。</summary>
public static partial class EventFilterBuilder
{
    public const int MaxIds = 30;

    public static readonly IReadOnlyList<EventLogPreset> LogPresets =
    [
        new("安全（Security）", "Security"),
        new("系统（System）", "System"),
        new("应用程序（Application）", "Application"),
        new("安装（Setup）", "Setup"),
        new("PowerShell（Windows PowerShell）", "Windows PowerShell"),
        new("转发的事件（ForwardedEvents）", "ForwardedEvents"),
        new("目录服务（Directory Service）", "Directory Service"),
        new("DNS 服务器（DNS Server）", "DNS Server"),
        new("DNS 客户端（Microsoft-Windows-DNS-Client/Operational）", "Microsoft-Windows-DNS-Client/Operational"),
        new("防火墙（Microsoft-Windows-Windows Firewall With Advanced Security/Firewall）",
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"),
        new("SMB 客户端连接（Microsoft-Windows-SmbClient/Connectivity）", "Microsoft-Windows-SmbClient/Connectivity"),
        new("远程桌面连接（Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational）",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
    ];

    public static readonly IReadOnlyList<EventIdPreset> IdPresets =
    [
        new("（不限事件 ID）", ""),
        new("4625（登录失败）", "4625"),
        new("4624（登录成功）", "4624"),
        new("4740（账户被锁定）", "4740"),
        new("4768,4769,4771（Kerberos 认证）", "4768,4769,4771"),
        new("4776（NTLM 凭据验证）", "4776"),
        new("4648（显式凭据登录）", "4648"),
        new("4672（特权登录）", "4672"),
        new("4719（审核策略被更改）", "4719"),
        new("1102（审核日志被清除）", "1102"),
        new("5152,5157（防火墙丢弃连接）", "5152,5157"),
        new("7036（服务状态变化）", "7036"),
        new("7045（安装新服务）", "7045"),
        new("41,6008（异常重启）", "41,6008"),
        new("1074（关机/重启原因）", "1074"),
        new("6005,6006（事件日志服务启停）", "6005,6006"),
    ];

    [GeneratedRegex(@"[（(]([^（）()]+)[）)]\s*$")]
    private static partial Regex TrailingParen();

    [GeneratedRegex(@"\d+")]
    private static partial Regex Number();

    /// <summary>
    /// 从下拉框文本取日志名：“安全（Security）”→ Security；直接输入的日志名原样使用。
    /// </summary>
    public static string ParseLogName(string? text)
    {
        var t = (text ?? "").Trim();
        var preset = LogPresets.FirstOrDefault(p => p.Display == t);
        if (preset is not null) return preset.LogName;
        var m = TrailingParen().Match(t);
        return m.Success ? m.Groups[1].Value.Trim() : t;
    }

    /// <summary>
    /// 解析事件 ID 输入：数字以逗号/空格/中文逗号/分号分隔；同时容忍预置文本中的中文说明。
    /// 非 1–65535 的数字记为错误；超过 <see cref="MaxIds"/> 个报错。
    /// </summary>
    public static IReadOnlyList<int> ParseIds(string? text, out IReadOnlyList<string> errors)
    {
        var errs = new List<string>();
        var ids = new List<int>();
        foreach (Match m in Number().Matches(text ?? ""))
        {
            if (!int.TryParse(m.Value, out var id) || id is < 1 or > 65535)
            {
                errs.Add($"事件 ID 需为 1–65535：{m.Value}");
                continue;
            }
            if (!ids.Contains(id)) ids.Add(id);
        }
        if (ids.Count > MaxIds)
        {
            errs.Add($"事件 ID 过多（{ids.Count}），最多 {MaxIds} 个");
            ids = ids.Take(MaxIds).ToList();
        }
        errors = errs;
        return ids;
    }

    /// <summary>构造 XPath；没有任何条件返回 "*"（全部）。</summary>
    public static string BuildXPath(
        IReadOnlyCollection<int> ids, EventLevelFilter level, TimeSpan? within)
    {
        var clauses = new List<string>();

        var levels = level switch
        {
            EventLevelFilter.Critical => new[] { 1 },
            EventLevelFilter.Error => [2],
            EventLevelFilter.Warning => [3],
            // 0 = LogAlways：安全审核等事件没有级别，按“信息”归类，否则 Security 日志选“信息”会查不到
            EventLevelFilter.Information => [0, 4],
            EventLevelFilter.Verbose => [5],
            EventLevelFilter.ErrorAndAbove => [1, 2],
            EventLevelFilter.WarningAndAbove => [1, 2, 3],
            _ => Array.Empty<int>(),
        };
        if (levels.Length > 0)
            clauses.Add("(" + string.Join(" or ", levels.Select(l => $"Level={l}")) + ")");

        if (ids.Count > 0)
            clauses.Add("(" + string.Join(" or ", ids.Select(i => $"EventID={i}")) + ")");

        if (within is { } span && span > TimeSpan.Zero)
        {
            var ms = (long)span.TotalMilliseconds;
            clauses.Add($"TimeCreated[timediff(@SystemTime) <= {ms}]");
        }

        if (clauses.Count == 0) return "*";
        var sb = new StringBuilder("*[System[");
        sb.Append(string.Join(" and ", clauses)).Append("]]");
        return sb.ToString();
    }
}
