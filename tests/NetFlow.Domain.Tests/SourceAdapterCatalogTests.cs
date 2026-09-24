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

    private static SourceAdapterOption Opt(string name, bool gateway, SourceAdapterKind kind) =>
        SourceAdapterCatalog.Create(name, [Ip("10.0.0.1")], gateway, kind)!;

    [Fact]
    public void PickDefault_优先带默认网关的以太网卡()
    {
        var vmnet = Opt("VMware VMnet1", gateway: false, SourceAdapterKind.Ethernet); // 虚拟网卡无网关
        var wifi = Opt("WLAN", gateway: true, SourceAdapterKind.Wireless);
        var eth = Opt("以太网", gateway: true, SourceAdapterKind.Ethernet);
        var vpn = Opt("VPN", gateway: true, SourceAdapterKind.Other);

        Assert.Equal("以太网", SourceAdapterCatalog.PickDefault([vmnet, wifi, vpn, eth])!.Name);
    }

    [Fact]
    public void PickDefault_没有以太网时退到带网关的无线_再退到任意网卡()
    {
        var vmnet = Opt("VMware VMnet1", gateway: false, SourceAdapterKind.Ethernet);
        var wifi = Opt("WLAN", gateway: true, SourceAdapterKind.Wireless);

        Assert.Equal("WLAN", SourceAdapterCatalog.PickDefault([vmnet, wifi])!.Name);
        Assert.Equal("VMware VMnet1", SourceAdapterCatalog.PickDefault([vmnet])!.Name);
        Assert.Null(SourceAdapterCatalog.PickDefault([]));
    }

    [Fact]
    public void Order_带网关优先_同级保持原顺序()
    {
        var a = Opt("A", gateway: false, SourceAdapterKind.Ethernet);
        var b = Opt("B", gateway: true, SourceAdapterKind.Ethernet);
        var c = Opt("C", gateway: true, SourceAdapterKind.Ethernet);

        Assert.Equal(["B", "C", "A"], SourceAdapterCatalog.Order([a, b, c]).Select(o => o.Name));
    }

    [Fact]
    public void Display_带默认网关的网卡加注()
    {
        Assert.Equal("以太网（10.0.0.1） · 默认网关", Opt("以太网", true, SourceAdapterKind.Ethernet).Display);
        Assert.Equal("VMnet1（10.0.0.1）", Opt("VMnet1", false, SourceAdapterKind.Ethernet).Display);
    }
}
