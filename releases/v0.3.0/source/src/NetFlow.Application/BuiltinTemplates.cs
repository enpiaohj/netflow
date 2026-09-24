using NetFlow.Domain;

namespace NetFlow.Application;

/// <summary>
/// 内置场景模板（设计文档 4.7 模板表）。
/// 关键约束：按"客户端→服务端"方向标注；不做"一键全部端口必开"假设；
/// 复制健康需要管理员授权且不能由端口测试替代（显式标注为独立检查）。
/// </summary>
public static class BuiltinTemplates
{
    public const string Version = "1.0.0";

    private const string StandardPerm =
        "域内普通用户权限（网络探测）；服务/事件查询需相应远端权限";

    public static readonly ScenarioTemplate AdClientToDc = new()
    {
        Id = "builtin.ad-client-dc",
        Name = "AD 客户端访问 DC",
        Description = "验证域内客户端能否正常发现、连接并使用域控制器的核心服务",
        Direction = "客户端 → 域控制器",
        Version = Version,
        RequiredPermission = StandardPerm + "；LDAP 认证测试需域凭据",
        Steps =
        [
            new ScenarioStep
            {
                Name = "DNS SRV（_ldap._tcp.dc._msdcs）",
                ProbeType = ProbeType.Dns,
                Parameters = new Dictionary<string, string>
                {
                    ["query"] = "_ldap._tcp.dc._msdcs.{domain}",
                    ["recordType"] = "SRV",
                    ["dnsServer"] = "target",
                },
            },
            new ScenarioStep
            {
                Name = "DNS A（DC 名称解析）",
                ProbeType = ProbeType.Dns,
                Parameters = new Dictionary<string, string>
                {
                    ["query"] = "{target}",
                    ["recordType"] = "A",
                    ["dnsServer"] = "target",
                },
            },
            new ScenarioStep
            {
                Name = "Kerberos 端口（TCP 88）",
                ProbeType = ProbeType.TcpConnect,
                Parameters = new Dictionary<string, string> { ["port"] = "88" },
            },
            new ScenarioStep
            {
                Name = "LDAP（TCP 389，匿名验证目录服务）",
                ProbeType = ProbeType.Ldap,
                Parameters = new Dictionary<string, string>
                {
                    ["port"] = "389",
                    ["bindMode"] = "anonymous",
                },
            },
            new ScenarioStep
            {
                Name = "SMB（TCP 445，SYSVOL 前提）",
                ProbeType = ProbeType.Smb,
                Parameters = new Dictionary<string, string> { ["port"] = "445" },
            },
            new ScenarioStep
            {
                Name = "RPC 端点映射（TCP 135）",
                ProbeType = ProbeType.TcpConnect,
                Parameters = new Dictionary<string, string> { ["port"] = "135" },
            },
            new ScenarioStep
            {
                Name = "NTP 时间同步（UDP 123）",
                ProbeType = ProbeType.Ntp,
            },
        ],
    };

    public static readonly ScenarioTemplate DcToDc = new()
    {
        Id = "builtin.dc-dc",
        Name = "DC 间通信",
        Description = "检查域控制器之间的基础网络互通（复制健康需另行授权检查，不能由端口测试替代）",
        Direction = "域控制器 → 域控制器",
        Version = Version,
        RequiredPermission = "至少网络可达；AD 复制状态检查需域管理员授权（本模板不替代）",
        Steps =
        [
            new ScenarioStep
            {
                Name = "DNS 服务（TCP 53，指向目标 DC）",
                ProbeType = ProbeType.TcpConnect,
                Parameters = new Dictionary<string, string> { ["port"] = "53" },
            },
            new ScenarioStep
            {
                Name = "Kerberos（TCP 88）",
                ProbeType = ProbeType.TcpConnect,
                Parameters = new Dictionary<string, string> { ["port"] = "88" },
            },
            new ScenarioStep
            {
                Name = "RPC 端点映射（TCP 135，动态端口另查）",
                ProbeType = ProbeType.TcpConnect,
                Parameters = new Dictionary<string, string> { ["port"] = "135" },
            },
            new ScenarioStep
            {
                Name = "LDAP（TCP 389，匿名验证目录服务）",
                ProbeType = ProbeType.Ldap,
                Parameters = new Dictionary<string, string>
                {
                    ["port"] = "389",
                    ["bindMode"] = "anonymous",
                },
            },
            new ScenarioStep
            {
                Name = "SMB（TCP 445）",
                ProbeType = ProbeType.Smb,
                Parameters = new Dictionary<string, string> { ["port"] = "445" },
            },
        ],
    };

    public static readonly ScenarioTemplate ExchangeClient = new()
    {
        Id = "builtin.exchange-client",
        Name = "Exchange 客户端",
        Description = "验证客户端访问 Exchange 的 DNS、TLS、HTTP 与 Autodiscover 路径",
        Direction = "客户端 → Exchange 服务器",
        Version = Version,
        RequiredPermission = StandardPerm,
        Steps =
        [
            new ScenarioStep
            {
                Name = "DNS 解析",
                ProbeType = ProbeType.Dns,
                Parameters = new Dictionary<string, string> { ["query"] = "{target}", ["recordType"] = "A" },
            },
            new ScenarioStep
            {
                Name = "HTTPS /owa",
                ProbeType = ProbeType.Http,
                Parameters = new Dictionary<string, string>
                {
                    ["url"] = "https://{target}/owa",
                    ["method"] = "GET",
                },
            },
            new ScenarioStep
            {
                Name = "TLS 证书检查",
                ProbeType = ProbeType.Tls,
                Parameters = new Dictionary<string, string> { ["port"] = "443" },
            },
            new ScenarioStep
            {
                Name = "Autodiscover（可选，按环境存在与否判定）",
                ProbeType = ProbeType.Http,
                Parameters = new Dictionary<string, string>
                {
                    ["url"] = "https://autodiscover.{domain}/autodiscover/autodiscover.xml",
                    ["method"] = "GET",
                },
            },
        ],
    };

    public static readonly ScenarioTemplate ExchangeMailFlow = new()
    {
        Id = "builtin.exchange-mailflow",
        Name = "Exchange 邮件流（SMTP）",
        Description = "检查 MX、SMTP Banner/EHLO 与 STARTTLS",
        Direction = "客户端 → 邮件服务器（按源/目标角色确定方向）",
        Version = Version,
        RequiredPermission = StandardPerm,
        Steps =
        [
            new ScenarioStep
            {
                Name = "MX 记录（可配置域名）",
                ProbeType = ProbeType.Dns,
                Parameters = new Dictionary<string, string>
                {
                    ["query"] = "{domain}",
                    ["recordType"] = "MX",
                },
            },
            new ScenarioStep
            {
                Name = "SMTP Banner / EHLO（TCP 25）",
                ProbeType = ProbeType.Smtp,
                Parameters = new Dictionary<string, string> { ["port"] = "25" },
            },
            new ScenarioStep
            {
                Name = "SMTP 提交端口（TCP 587，可选）",
                ProbeType = ProbeType.Smtp,
                Parameters = new Dictionary<string, string> { ["port"] = "587" },
            },
        ],
    };

    public static readonly ScenarioTemplate SqlServer = new()
    {
        Id = "builtin.sql-server",
        Name = "SQL Server",
        Description = "默认实例直测 TCP 1433（命名实例经 Browser UDP 1434 发现端口）→ 可选登录",
        Direction = "客户端 → SQL Server",
        Version = Version,
        RequiredPermission = StandardPerm + "；登录测试需 SQL 凭据或 Windows 集成身份",
        Steps =
        [
            new ScenarioStep
            {
                Name = "TCP 连接（默认 1433）+ 可选登录",
                ProbeType = ProbeType.SqlServer,
                Parameters = new Dictionary<string, string>
                {
                    ["browser"] = "auto",
                    ["tryLogin"] = "true",
                },
            },
        ],
    };

    public static readonly ScenarioTemplate WebApi = new()
    {
        Id = "builtin.web-api",
        Name = "Web/API",
        Description = "DNS、TCP、TLS、HTTP 规则与时间分解",
        Direction = "客户端 → Web/API 服务器",
        Version = Version,
        RequiredPermission = StandardPerm,
        Steps =
        [
            new ScenarioStep
            {
                Name = "HTTPS 请求（分阶段耗时）",
                ProbeType = ProbeType.Http,
                Parameters = new Dictionary<string, string>
                {
                    ["url"] = "https://{target}",
                    ["method"] = "GET",
                },
            },
            new ScenarioStep
            {
                Name = "TLS 证书检查",
                ProbeType = ProbeType.Tls,
                Parameters = new Dictionary<string, string> { ["port"] = "443" },
            },
        ],
    };

    public static readonly ScenarioTemplate SmbShare = new()
    {
        Id = "builtin.smb-share",
        Name = "SMB 文件共享",
        Description = "DNS、445、SMB 协商；共享权限按明确身份验证（本模板不含）",
        Direction = "客户端 → 文件服务器",
        Version = Version,
        RequiredPermission = StandardPerm,
        Steps =
        [
            new ScenarioStep
            {
                Name = "SMB2 协商（TCP 445）",
                ProbeType = ProbeType.Smb,
                Parameters = new Dictionary<string, string> { ["port"] = "445" },
            },
        ],
    };

    public static readonly ScenarioTemplate RemoteManagement = new()
    {
        Id = "builtin.remote-mgmt",
        Name = "远程管理",
        Description = "WinRM、RDP、SSH 的连接与最小化握手",
        Direction = "客户端 → 管理目标",
        Version = Version,
        RequiredPermission = StandardPerm,
        Steps =
        [
            new ScenarioStep
            {
                Name = "RDP（TCP 3389 + X.224）",
                ProbeType = ProbeType.Rdp,
                Parameters = new Dictionary<string, string> { ["port"] = "3389" },
            },
            new ScenarioStep
            {
                Name = "WinRM HTTP（TCP 5985 + WS-Man Identify）",
                ProbeType = ProbeType.WinRm,
                Parameters = new Dictionary<string, string> { ["port"] = "5985" },
            },
            new ScenarioStep
            {
                Name = "SSH（TCP 22，可选）",
                ProbeType = ProbeType.Ssh,
                Parameters = new Dictionary<string, string> { ["port"] = "22", ["optional"] = "true" },
            },
        ],
    };

    public static readonly ScenarioTemplate NtpCheck = new()
    {
        Id = "builtin.ntp",
        Name = "NTP 时间源",
        Description = "指定时间源的有效响应、往返与偏差对比",
        Direction = "客户端 → 时间源",
        Version = Version,
        RequiredPermission = StandardPerm,
        Steps =
        [
            new ScenarioStep
            {
                Name = "NTP 请求（UDP 123）",
                ProbeType = ProbeType.Ntp,
            },
        ],
    };

    public static IReadOnlyList<ScenarioTemplate> All =>
    [
        AdClientToDc, DcToDc, ExchangeClient, ExchangeMailFlow,
        SqlServer, WebApi, SmbShare, RemoteManagement, NtpCheck,
    ];

    public static ScenarioTemplate? Find(string? id) =>
        All.FirstOrDefault(t => string.Equals(t.Id, id, StringComparison.OrdinalIgnoreCase));
}
