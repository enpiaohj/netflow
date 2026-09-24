using NetFlow.Windows;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>事件日志筛选：日志名解析、事件 ID 解析与 XPath 构造。</summary>
public class EventFilterBuilderTests
{
    [Theory]
    [InlineData("安全（Security）", "Security")]
    [InlineData("Security", "Security")]
    [InlineData("  System  ", "System")]
    [InlineData("DNS 客户端（Microsoft-Windows-DNS-Client/Operational）", "Microsoft-Windows-DNS-Client/Operational")]
    [InlineData("自定义日志 (My-Log/Operational)", "My-Log/Operational")]
    public void ParseLogName_预置中文显示与手输都能解析(string text, string expected) =>
        Assert.Equal(expected, EventFilterBuilder.ParseLogName(text));

    [Fact]
    public void 所有日志预置的显示文本都能还原为其日志名()
    {
        Assert.All(EventFilterBuilder.LogPresets, p =>
            Assert.Equal(p.LogName, EventFilterBuilder.ParseLogName(p.Display)));
    }

    [Theory]
    [InlineData("4625", new[] { 4625 })]
    [InlineData("4625, 4624；4740 4625", new[] { 4625, 4624, 4740 })] // 多种分隔符 + 去重
    [InlineData("4768,4769,4771（Kerberos 认证）", new[] { 4768, 4769, 4771 })] // 容忍预置文本
    [InlineData("", new int[0])]
    public void ParseIds_多种分隔符(string text, int[] expected)
    {
        var ids = EventFilterBuilder.ParseIds(text, out var errors);
        Assert.Equal(expected, ids);
        Assert.Empty(errors);
    }

    [Fact]
    public void ParseIds_越界与过多报错()
    {
        EventFilterBuilder.ParseIds("0, 70000, 4625", out var errors1);
        Assert.Equal(2, errors1.Count);

        var many = string.Join(",", Enumerable.Range(1000, EventFilterBuilder.MaxIds + 5));
        var ids = EventFilterBuilder.ParseIds(many, out var errors2);
        Assert.Equal(EventFilterBuilder.MaxIds, ids.Count);
        Assert.Single(errors2);
    }

    [Fact]
    public void 所有事件ID预置都能解析且无错误()
    {
        Assert.All(EventFilterBuilder.IdPresets, p =>
        {
            EventFilterBuilder.ParseIds(p.Ids, out var errors);
            Assert.Empty(errors);
        });
    }

    [Fact]
    public void BuildXPath_无条件返回全部()
    {
        Assert.Equal("*", EventFilterBuilder.BuildXPath([], EventLevelFilter.All, null));
    }

    [Fact]
    public void BuildXPath_组合级别_事件ID_时间范围()
    {
        var xpath = EventFilterBuilder.BuildXPath(
            [4625, 4624], EventLevelFilter.WarningAndAbove, TimeSpan.FromHours(1));

        Assert.Equal(
            "*[System[(Level=1 or Level=2 or Level=3) and (EventID=4625 or EventID=4624) " +
            "and TimeCreated[timediff(@SystemTime) <= 3600000]]]",
            xpath);
    }

    [Fact]
    public void BuildXPath_信息级别包含始终记录的Level0()
    {
        // 安全审核事件没有级别（Level=0），选“信息”时也要能查到
        Assert.Contains("Level=0", EventFilterBuilder.BuildXPath([], EventLevelFilter.Information, null));
    }

    [Fact]
    public void BuildXPath_仅事件ID()
    {
        Assert.Equal("*[System[(EventID=7036)]]",
            EventFilterBuilder.BuildXPath([7036], EventLevelFilter.All, null));
    }
}
