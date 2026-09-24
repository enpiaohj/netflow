using System.Text.RegularExpressions;

namespace NetFlow.Application;

public enum PortProtocol
{
    Tcp,
    Udp,
}

/// <summary>常见端口条目（用于端口下拉与端口包内置数据）。</summary>
public sealed record WellKnownPort(PortProtocol Protocol, int Port, string Name)
{
    /// <summary>下拉框显示，如 “445 SMB 文件共享”。解析时只取前面的数字。</summary>
    public string Display => $"{Port} {Name}";
}

/// <summary>常见端口目录。排序即下拉顺序：数据库与最常用的排前面。</summary>
public static partial class WellKnownPorts
{
    public static readonly IReadOnlyList<WellKnownPort> Tcp =
    [
        new(PortProtocol.Tcp, 445, "SMB 文件共享"),
        new(PortProtocol.Tcp, 1433, "SQL Server"),
        new(PortProtocol.Tcp, 3306, "MySQL / MariaDB"),
        new(PortProtocol.Tcp, 5432, "PostgreSQL"),
        new(PortProtocol.Tcp, 1521, "Oracle"),
        new(PortProtocol.Tcp, 6379, "Redis"),
        new(PortProtocol.Tcp, 27017, "MongoDB"),
        new(PortProtocol.Tcp, 3389, "远程桌面 RDP"),
        new(PortProtocol.Tcp, 5985, "WinRM（HTTP）"),
        new(PortProtocol.Tcp, 5986, "WinRM（HTTPS）"),
        new(PortProtocol.Tcp, 22, "SSH"),
        new(PortProtocol.Tcp, 80, "HTTP"),
        new(PortProtocol.Tcp, 443, "HTTPS"),
        new(PortProtocol.Tcp, 8080, "HTTP 备用"),
        new(PortProtocol.Tcp, 8443, "HTTPS 备用"),
        new(PortProtocol.Tcp, 53, "DNS"),
        new(PortProtocol.Tcp, 88, "Kerberos"),
        new(PortProtocol.Tcp, 135, "RPC 端点映射"),
        new(PortProtocol.Tcp, 139, "NetBIOS 会话"),
        new(PortProtocol.Tcp, 389, "LDAP"),
        new(PortProtocol.Tcp, 636, "LDAPS"),
        new(PortProtocol.Tcp, 464, "Kerberos 改密"),
        new(PortProtocol.Tcp, 3268, "全局编录"),
        new(PortProtocol.Tcp, 3269, "全局编录（SSL）"),
        new(PortProtocol.Tcp, 9389, "AD Web 服务"),
        new(PortProtocol.Tcp, 25, "SMTP"),
        new(PortProtocol.Tcp, 465, "SMTPS"),
        new(PortProtocol.Tcp, 587, "SMTP 提交"),
        new(PortProtocol.Tcp, 110, "POP3"),
        new(PortProtocol.Tcp, 995, "POP3S"),
        new(PortProtocol.Tcp, 143, "IMAP"),
        new(PortProtocol.Tcp, 993, "IMAPS"),
        new(PortProtocol.Tcp, 33060, "MySQL X 协议"),
    ];

    public static readonly IReadOnlyList<WellKnownPort> Udp =
    [
        new(PortProtocol.Udp, 123, "NTP 时间同步"),
        new(PortProtocol.Udp, 53, "DNS"),
        new(PortProtocol.Udp, 88, "Kerberos"),
        new(PortProtocol.Udp, 389, "CLDAP"),
        new(PortProtocol.Udp, 464, "Kerberos 改密"),
        new(PortProtocol.Udp, 1434, "SQL Server Browser"),
        new(PortProtocol.Udp, 137, "NetBIOS 名称"),
        new(PortProtocol.Udp, 138, "NetBIOS 数据报"),
        new(PortProtocol.Udp, 161, "SNMP"),
        new(PortProtocol.Udp, 162, "SNMP Trap"),
        new(PortProtocol.Udp, 500, "IKE（IPsec）"),
        new(PortProtocol.Udp, 4500, "IPsec NAT-T"),
        new(PortProtocol.Udp, 514, "Syslog"),
        new(PortProtocol.Udp, 1812, "RADIUS 认证"),
        new(PortProtocol.Udp, 1813, "RADIUS 计费"),
        new(PortProtocol.Udp, 67, "DHCP 服务器"),
        new(PortProtocol.Udp, 5353, "mDNS"),
    ];

    /// <summary>查目录中的端口名称；没有返回空串。</summary>
    public static string NameOf(PortProtocol protocol, int port) =>
        (protocol == PortProtocol.Tcp ? Tcp : Udp).FirstOrDefault(p => p.Port == port)?.Name ?? "";

    [GeneratedRegex(@"^\s*(\d{1,5})")]
    private static partial Regex LeadingNumber();

    /// <summary>
    /// 从下拉框文本解析端口：接受 “445”、“445 SMB 文件共享”。超出 1–65535 或没有数字返回 null。
    /// </summary>
    public static int? ParsePort(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var m = LeadingNumber().Match(text);
        if (!m.Success) return null;
        return int.TryParse(m.Groups[1].Value, out var port) && port is >= 1 and <= 65535 ? port : null;
    }
}
