using NetFlow.Application;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>端口目录、端口包文本格式、内置端口包与批量展开。</summary>
public class PortPackTests
{
    [Theory]
    [InlineData("445", 445)]
    [InlineData("1433 SQL Server", 1433)]
    [InlineData("  3306 MySQL / MariaDB", 3306)]
    [InlineData("65535", 65535)]
    public void ParsePort_取前导数字(string text, int expected) =>
        Assert.Equal(expected, WellKnownPorts.ParsePort(text));

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData(null)]
    public void ParsePort_非法输入返回null(string? text) =>
        Assert.Null(WellKnownPorts.ParsePort(text));

    [Fact]
    public void 常见端口目录_包含SQLServer与MySQL等数据库()
    {
        Assert.Contains(WellKnownPorts.Tcp, p => p.Port == 1433 && p.Name.Contains("SQL Server"));
        Assert.Contains(WellKnownPorts.Tcp, p => p.Port == 3306 && p.Name.Contains("MySQL"));
        Assert.Contains(WellKnownPorts.Tcp, p => p.Port == 5432 && p.Name.Contains("PostgreSQL"));
        Assert.Contains(WellKnownPorts.Udp, p => p.Port == 123 && p.Name.Contains("NTP"));
        // 同协议内端口不重复
        Assert.Equal(WellKnownPorts.Tcp.Count, WellKnownPorts.Tcp.Select(p => p.Port).Distinct().Count());
        Assert.Equal(WellKnownPorts.Udp.Count, WellKnownPorts.Udp.Select(p => p.Port).Distinct().Count());
    }

    [Fact]
    public void Parse_支持多种写法与注释_默认TCP()
    {
        var result = PortPackText.Parse("""
            tcp/445 SMB 文件共享
            UDP:123
            3389/tcp
            1433            # 只写端口按 TCP
            # 整行注释

            """);

        Assert.Empty(result.Errors);
        Assert.Equal(
        [
            new PortEntry(PortProtocol.Tcp, 445, "SMB 文件共享"),
            new PortEntry(PortProtocol.Udp, 123, "NTP 时间同步"), // 省略说明取常见端口名
            new PortEntry(PortProtocol.Tcp, 3389, "远程桌面 RDP"),
            new PortEntry(PortProtocol.Tcp, 1433, "SQL Server"),
        ], result.Entries);
    }

    [Fact]
    public void Parse_重复项忽略_错误行带行号()
    {
        var result = PortPackText.Parse("tcp/80\ntcp/80\nhello\ntcp/70000");

        Assert.Single(result.Entries);
        Assert.Equal(2, result.Errors.Count);
        Assert.Contains(result.Errors, e => e.Contains("第 3 行"));
        Assert.Contains(result.Errors, e => e.Contains("第 4 行") && e.Contains("70000"));
    }

    [Fact]
    public void Format与Parse互逆()
    {
        var original = PortPackText.Parse("tcp/445 SMB\nudp/123 NTP\ntcp/8081 自定义").Entries;
        var again = PortPackText.Parse(PortPackText.Format(original)).Entries;
        Assert.Equal(original, again);
    }

    [Fact]
    public void 内置端口包_Id与名称唯一_端口合法_包含AD数据库包()
    {
        var packs = BuiltinPortPacks.All;
        Assert.Equal(packs.Count, packs.Select(p => p.Id).Distinct().Count());
        Assert.Equal(packs.Count, packs.Select(p => p.Name).Distinct().Count());
        Assert.All(packs, p =>
        {
            Assert.True(p.IsBuiltin);
            Assert.NotEmpty(p.Entries);
            Assert.All(p.Entries, e => Assert.InRange(e.Port, 1, 65535));
            // 包内 (协议,端口) 不重复
            Assert.Equal(p.Entries.Count, p.Entries.Select(e => (e.Protocol, e.Port)).Distinct().Count());
        });

        var ad = packs.Single(p => p.Name == "客户端 → AD 域控");
        foreach (var port in new[] { 53, 88, 135, 389, 445, 464, 636, 3268, 3269 })
            Assert.Contains(ad.Entries, e => e.Protocol == PortProtocol.Tcp && e.Port == port);
        Assert.Contains(ad.Entries, e => e.Protocol == PortProtocol.Udp && e.Port == 123);

        var db = packs.Single(p => p.Name == "常见数据库");
        Assert.Contains(db.Entries, e => e.Port == 1433);
        Assert.Contains(db.Entries, e => e.Port == 3306);
    }

    [Fact]
    public void Expand_主机乘以端口包_host冒号port只测该端口()
    {
        var pack = BuiltinPortPacks.All.Single(p => p.Name == "SQL Server");
        var result = PortPackExpander.Expand(["10.0.0.1", "db01", "10.0.0.9:5000", "# 注释", ""], pack);

        Assert.Empty(result.Errors);
        // 2 台主机 × 包内 2 项 + 1 个显式端口
        Assert.Equal(5, result.Targets.Count);
        Assert.Contains(result.Targets, t => t.Host == "10.0.0.9" && t.Entry.Port == 5000
            && t.Entry.Protocol == PortProtocol.Tcp);
        Assert.Equal(2, result.Targets.Count(t => t.Host == "db01"));
    }

    [Fact]
    public void Expand_无端口包时不带端口的行报错()
    {
        var result = PortPackExpander.Expand(["10.0.0.1", "10.0.0.2:445"], pack: null);

        Assert.Single(result.Targets);
        Assert.Single(result.Errors);
        Assert.Contains("10.0.0.1", result.Errors[0]);
    }

    [Fact]
    public void Expand_IPv6字面量按主机处理_重复项去重_坏端口报错()
    {
        var pack = new PortPack
        {
            Id = "t", Name = "t", Entries = [new PortEntry(PortProtocol.Tcp, 443, "")],
        };
        var result = PortPackExpander.Expand(["2001:db8::1", "2001:db8::1", "host:99999"], pack);

        Assert.Single(result.Targets);
        Assert.Equal("2001:db8::1", result.Targets[0].Host);
        Assert.Single(result.Errors);
    }

    [Theory]
    [InlineData("", null, null, null)]
    [InlineData("1433", 1433, null, null)]
    [InlineData("1444 自定义端口", 1444, null, null)]
    [InlineData("MSSQLSERVER", null, null, null)]
    [InlineData("SQLEXPRESS", null, "SQLEXPRESS", null)]
    [InlineData(@"DB01\PROD", null, "PROD", null)]
    [InlineData("SQLEXPRESS 命名实例（经 Browser 发现）", null, "SQLEXPRESS", null)] // 下拉预置带中文说明
    [InlineData("MSSQLSERVER 默认实例", null, null, null)]
    [InlineData("1433 默认实例（TCP 直连）", 1433, null, null)]
    public void SqlTargetParser_端口_实例_默认实例(string text, int? port, string? instance, string? error)
    {
        var r = SqlTargetParser.Parse(text);
        Assert.Equal(port, r.Port);
        Assert.Equal(instance, r.InstanceName);
        Assert.Equal(error, r.Error);
    }

    [Theory]
    [InlineData("70000")]
    [InlineData("bad!name")]
    public void SqlTargetParser_非法输入报错(string text) =>
        Assert.NotNull(SqlTargetParser.Parse(text).Error);
}
