using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace NetFlow.Application;

/// <summary>端口包中的一项：协议 + 端口 + 说明。</summary>
public sealed record PortEntry(PortProtocol Protocol, int Port, string Name)
{
    /// <summary>如 “TCP 445 SMB 文件共享”。</summary>
    public string Display =>
        $"{(Protocol == PortProtocol.Tcp ? "TCP" : "UDP")} {Port}" + (Name.Length > 0 ? $" {Name}" : "");
}

/// <summary>端口包：一组预置的端口，批量测试时对每台主机展开执行。</summary>
public sealed record PortPack
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public string Description { get; init; } = "";

    public required IReadOnlyList<PortEntry> Entries { get; init; }

    /// <summary>内置端口包只读；用户可另存为自定义端口包。</summary>
    public bool IsBuiltin { get; init; }
}

public sealed record PortPackParseResult(IReadOnlyList<PortEntry> Entries, IReadOnlyList<string> Errors);

/// <summary>
/// 端口包文本格式：一行一项，<c>tcp/445 SMB 文件共享</c>、<c>udp/123 NTP</c>、<c>445/tcp</c>；
/// 只写端口号视为 TCP；# 之后为注释；说明可省略（自动取常见端口名称）。
/// </summary>
public static partial class PortPackText
{
    public const int MaxEntries = 200;

    [GeneratedRegex(@"^(?:(?<p>tcp|udp)\s*[/:]\s*)?(?<port>\d{1,5})(?:\s*/\s*(?<p2>tcp|udp))?(?:\s+(?<name>.*))?$",
        RegexOptions.IgnoreCase)]
    private static partial Regex Line();

    public static PortPackParseResult Parse(string? text)
    {
        var entries = new List<PortEntry>();
        var errors = new List<string>();
        var seen = new HashSet<(PortProtocol, int)>();

        var lineNo = 0;
        foreach (var raw in (text ?? "").Split('\n'))
        {
            lineNo++;
            var line = raw.Trim('\r', ' ', '\t');
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash].TrimEnd();
            if (line.Length == 0) continue;

            var m = Line().Match(line);
            if (!m.Success)
            {
                errors.Add($"第 {lineNo} 行无法识别：{line}（应为 tcp/445 或 udp/123 [说明]）");
                continue;
            }

            var protoText = m.Groups["p"].Success ? m.Groups["p"].Value
                : m.Groups["p2"].Success ? m.Groups["p2"].Value : "tcp";
            var protocol = protoText.Equals("udp", StringComparison.OrdinalIgnoreCase)
                ? PortProtocol.Udp : PortProtocol.Tcp;

            if (!int.TryParse(m.Groups["port"].Value, out var port) || port is < 1 or > 65535)
            {
                errors.Add($"第 {lineNo} 行端口超出 1–65535：{m.Groups["port"].Value}");
                continue;
            }

            if (!seen.Add((protocol, port))) continue; // 重复项忽略

            var name = m.Groups["name"].Success ? m.Groups["name"].Value.Trim() : "";
            if (name.Length == 0) name = WellKnownPorts.NameOf(protocol, port);
            entries.Add(new PortEntry(protocol, port, name));
        }

        if (entries.Count > MaxEntries)
        {
            errors.Add($"端口项过多（{entries.Count}），最多 {MaxEntries} 项");
            entries = entries.Take(MaxEntries).ToList();
        }
        return new PortPackParseResult(entries, errors);
    }

    public static string Format(IEnumerable<PortEntry> entries)
    {
        var sb = new StringBuilder();
        foreach (var e in entries)
        {
            sb.Append(e.Protocol == PortProtocol.Tcp ? "tcp" : "udp").Append('/').Append(e.Port);
            if (e.Name.Length > 0) sb.Append(' ').Append(e.Name);
            sb.Append('\n');
        }
        return sb.ToString().TrimEnd('\n');
    }
}

/// <summary>内置端口包（只读）。</summary>
public static class BuiltinPortPacks
{
    private static PortEntry T(int port, string name = "") => new(PortProtocol.Tcp, port, name.Length > 0 ? name : WellKnownPorts.NameOf(PortProtocol.Tcp, port));

    private static PortEntry U(int port, string name = "") => new(PortProtocol.Udp, port, name.Length > 0 ? name : WellKnownPorts.NameOf(PortProtocol.Udp, port));

    private static PortPack Pack(string id, string name, string description, params PortEntry[] entries) =>
        new() { Id = $"builtin.{id}", Name = name, Description = description, Entries = entries, IsBuiltin = true };

    public static readonly IReadOnlyList<PortPack> All =
    [
        Pack("ad-client", "客户端 → AD 域控",
            "域成员/客户端访问域控所需端口：DNS、Kerberos、LDAP、SMB、RPC、全局编录、时间同步",
            T(53), T(88), T(135), T(389), T(445), T(464), T(636), T(3268), T(3269),
            U(53), U(88), U(123), U(389), U(464)),
        Pack("ad-dc", "域控 ↔ 域控（复制）",
            "域控间复制与管理：在“客户端 → AD”基础上增加 AD Web 服务与 DFS-R",
            T(53), T(88), T(135), T(389), T(445), T(464), T(636), T(3268), T(3269), T(9389), T(5722, "DFS-R"),
            U(53), U(88), U(123), U(389), U(464)),
        Pack("smb", "文件共享（SMB）", "SMB 直连与 NetBIOS 兼容端口",
            T(445), T(139), U(137), U(138)),
        Pack("db-common", "常见数据库", "SQL Server、MySQL/MariaDB、PostgreSQL、Oracle、MongoDB、Redis",
            T(1433), T(3306), T(5432), T(1521), T(27017), T(6379), U(1434)),
        Pack("sqlserver", "SQL Server", "默认实例 TCP 1433 与 Browser 服务 UDP 1434",
            T(1433), U(1434)),
        Pack("mysql", "MySQL / MariaDB", "经典协议 3306 与 X 协议 33060",
            T(3306), T(33060)),
        Pack("postgresql", "PostgreSQL", "默认监听端口 5432", T(5432)),
        Pack("mail", "邮件（Exchange / SMTP / IMAP / POP3）", "SMTP、提交、IMAP、POP3 及其加密端口",
            T(25), T(465), T(587), T(110), T(995), T(143), T(993), T(80), T(443)),
        Pack("web", "Web 服务", "HTTP/HTTPS 及常见备用端口",
            T(80), T(443), T(8080), T(8443)),
        Pack("remote-admin", "远程管理", "SSH、远程桌面、WinRM、RPC、SMB",
            T(22), T(3389), T(5985), T(5986), T(135), T(445)),
        Pack("dns", "DNS 服务", "DNS 的 TCP 与 UDP 53", T(53), U(53)),
        Pack("ntp", "时间同步（NTP）", "UDP 123", U(123)),
    ];
}

/// <summary>批量测试中的一项：主机 + 端口项。</summary>
public sealed record BatchTarget(string Host, PortEntry Entry);

public sealed record BatchExpansion(IReadOnlyList<BatchTarget> Targets, IReadOnlyList<string> Errors);

/// <summary>把“主机列表 × 端口包”展开成批量测试项。</summary>
public static class PortPackExpander
{
    public const int MaxTargets = 2000;

    /// <summary>
    /// 主机行：<c>host</c>（按端口包展开）或 <c>host:port</c>（只测该 TCP 端口）。
    /// IPv6 字面量不带端口写法，按主机处理。pack 为 null 时，不带端口的行报错。
    /// </summary>
    public static BatchExpansion Expand(IEnumerable<string> lines, PortPack? pack)
    {
        var targets = new List<BatchTarget>();
        var errors = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in lines)
        {
            var line = raw.Trim();
            var hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash].TrimEnd();
            if (line.Length == 0) continue;

            string host = line;
            int? explicitPort = null;
            if (!IPAddress.TryParse(line, out _))
            {
                var colon = line.LastIndexOf(':');
                if (colon > 0 && line.IndexOf(':') == colon) // 恰有一个冒号：host:port
                {
                    if (!int.TryParse(line[(colon + 1)..], out var p) || p is < 1 or > 65535)
                    {
                        errors.Add($"端口无效：{line}");
                        continue;
                    }
                    host = line[..colon].Trim();
                    explicitPort = p;
                }
            }

            if (host.Length == 0)
            {
                errors.Add($"主机为空：{line}");
                continue;
            }

            IEnumerable<PortEntry> entries;
            if (explicitPort is { } port)
            {
                entries = [new PortEntry(PortProtocol.Tcp, port, WellKnownPorts.NameOf(PortProtocol.Tcp, port))];
            }
            else if (pack is not null)
            {
                entries = pack.Entries;
            }
            else
            {
                errors.Add($"“{host}”没有指定端口：请写成 host:port，或选择一个端口包");
                continue;
            }

            foreach (var entry in entries)
            {
                if (!seen.Add($"{host}|{entry.Protocol}|{entry.Port}")) continue;
                targets.Add(new BatchTarget(host, entry));
            }
        }

        if (targets.Count > MaxTargets)
        {
            errors.Add($"测试项过多（{targets.Count}），单次最多 {MaxTargets} 项，请减少主机或端口");
            targets = targets.Take(MaxTargets).ToList();
        }
        return new BatchExpansion(targets, errors);
    }
}
