using System.Text.Json;

namespace NetFlow.Windows;

/// <summary>Windows 防火墙规则快照（设计文档 4.1：规则是配置证据，非有效路径证明）。</summary>
public sealed record FirewallRuleInfo
{
    public required string Name { get; init; }
    public required string DisplayName { get; init; }
    public required bool Enabled { get; init; }
    public required string Direction { get; init; }
    public required string Action { get; init; }
    public required string Profile { get; init; }
    public required string Program { get; init; }
    public required string Service { get; init; }
    public required string LocalPorts { get; init; }
    public required string RemotePorts { get; init; }
    public required string LocalAddresses { get; init; }
    public required string RemoteAddresses { get; init; }
    public required string Protocol { get; init; }
}

/// <summary>
/// Windows 防火墙规则读取。使用 PowerShell NetSecurity 官方模块（固定路径、参数数组）。
/// 展示的是配置事实，不能据此判定流量真实被放行。
/// </summary>
public static class FirewallReader
{
    public static async Task<IReadOnlyList<FirewallRuleInfo>> CollectRulesAsync(
        string? nameFilter = null, int maxRules = 500, CancellationToken ct = default)
    {
        var filter = nameFilter is null
            ? ""
            : $"-DisplayName '{nameFilter.Replace('\'', ' ')}'";
        // 注意：脚本含 PowerShell scriptblock 的 {}，用普通原始字符串拼参数，避免内插转义
        var script = """
            Get-NetFirewallRule FILTER -PolicyStore ActiveStore |
              Select-Object -First MAX | ForEach-Object {
                $p = $_ | Get-NetFirewallPortFilter;
                $a = $_ | Get-NetFirewallAddressFilter;
                $s = $_ | Get-NetFirewallServiceFilter;
                [pscustomobject]@{
                  Name=$_.Name; DisplayName=$_.DisplayName; Enabled=$_.Enabled;
                  Direction=$_.Direction; Action=$_.Action; Profile=($_.Profile -join ',');
                  Program=$p.Program; Service=$s.Service;
                  LocalPorts=($p.LocalPort -join ','); RemotePorts=($p.RemotePort -join ',');
                  LocalAddresses=($a.LocalAddress -join ','); RemoteAddresses=($a.RemoteAddress -join ',');
                  Protocol=$p.Protocol
                }
              } | ConvertTo-Json -Compress -Depth 3
            """.Replace("FILTER", filter).Replace("MAX", maxRules.ToString());

        var result = await ProcessRunner.RunPowerShellAsync(script,
            TimeSpan.FromMinutes(3), ct).ConfigureAwait(false);
        if (!result.Succeeded)
            throw new InvalidOperationException(
                $"防火墙规则查询失败（exit {result.ExitCode}）：{result.StandardError.Trim()}");
        return ParseRulesJson(result.StandardOutput);
    }

    public static IReadOnlyList<FirewallRuleInfo> ParseRulesJson(string json)
    {
        var list = new List<FirewallRuleInfo>();
        if (string.IsNullOrWhiteSpace(json)) return list;
        var node = JsonDocument.Parse(json.Trim()).RootElement;
        IEnumerable<JsonElement> items = node.ValueKind == JsonValueKind.Array
            ? node.EnumerateArray()
            : [node];
        foreach (var item in items)
        {
            list.Add(new FirewallRuleInfo
            {
                Name = Str(item, "Name"),
                DisplayName = Str(item, "DisplayName"),
                Enabled = Str(item, "Enabled").Equals("True", StringComparison.OrdinalIgnoreCase),
                Direction = Str(item, "Direction"),
                Action = Str(item, "Action"),
                Profile = Str(item, "Profile"),
                Program = Str(item, "Program"),
                Service = Str(item, "Service"),
                LocalPorts = Str(item, "LocalPorts"),
                RemotePorts = Str(item, "RemotePorts"),
                LocalAddresses = Str(item, "LocalAddresses"),
                RemoteAddresses = Str(item, "RemoteAddresses"),
                Protocol = Str(item, "Protocol"),
            });
        }
        return list;
    }

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) ? v.ToString() : "";
}
