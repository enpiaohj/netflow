using System.Net;
using System.Net.Sockets;
using NetFlow.Application;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>源网卡候选筛选与按协议族取地址（多网卡/VPN 环境的源地址选择）。</summary>
public class SourceAdapterCatalogTests
{
    private static IPAddress Ip(string s) => IPAddress.Parse(s);

    [Theory]
    [InlineData("192.168.10.100", true)]
    [InlineData("10.0.0.5", true)]
    [InlineData("2001:db8::10", true)]
    [InlineData("127.0.0.1", false)]        // 回环
    [InlineData("::1", false)]              // 回环
    [InlineData("169.254.220.23", false)]   // IPv4 自动私有地址（无 DHCP）
    [InlineData("fe80::1234", false)]       // IPv6 链路本地
    public void IsUsableSource_过滤不可用于出包的地址(string address, bool expected)
    {
        Assert.Equal(expected, SourceAdapterCatalog.IsUsableSource(Ip(address)));
    }

    [Fact]
    public void Create_只有不可用地址的网卡不出现在候选中()
    {
        var option = SourceAdapterCatalog.Create("WLAN", [Ip("169.254.220.23"), Ip("fe80::1")]);
        Assert.Null(option);
    }

    [Fact]
    public void Create_保留可用地址并丢弃不可用地址()
    {
        var option = SourceAdapterCatalog.Create(
            "以太网", [Ip("fe80::1"), Ip("192.168.10.100"), Ip("169.254.1.1"), Ip("2001:db8::10")]);

        Assert.NotNull(option);
        Assert.Equal([Ip("192.168.10.100"), Ip("2001:db8::10")], option!.Addresses);
    }

    [Fact]
    public void PickFor_按目标协议族取地址_无对应协议族返回null()
    {
        var v4Only = SourceAdapterCatalog.Create("以太网", [Ip("192.168.10.100")])!;

        Assert.Equal(Ip("192.168.10.100"), v4Only.PickFor(AddressFamily.InterNetwork));
        // IPv4 源地址无法连接 IPv6 目标：必须返回 null 由调用方报错，而不是错误绑定
        Assert.Null(v4Only.PickFor(AddressFamily.InterNetworkV6));
    }

    [Fact]
    public void Display_优先展示IPv4()
    {
        var option = SourceAdapterCatalog.Create("以太网", [Ip("2001:db8::10"), Ip("192.168.10.100")])!;
        Assert.Equal("以太网（192.168.10.100）", option.Display);
    }
}
