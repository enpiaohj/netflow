using System.Net;
using NetFlow.Domain;
using NetFlow.Probes;
using Xunit;

namespace NetFlow.Probes.Tests;

/// <summary>无法绑定源地址的探针必须如实标注，不得把“请求的源地址”写成本次实际源地址。</summary>
public class SourceAddressHonestyTests
{
    private static ProbeRequest Request(IPAddress? source) => new()
    {
        RunId = RunId.New(),
        SourceAddress = source,
        Parameters = new ProbeParameters
        {
            ProbeType = ProbeType.IcmpPing,
            RequestedTarget = "127.0.0.1",
            Timeout = TimeSpan.FromSeconds(1),
        },
    };

    [Fact]
    public async Task Icmp_IPv4源地址访问IPv4目标时真正绑定并记录实际源地址()
    {
        var run = await new IcmpProbe().ExecuteAsync(
            IPAddress.Loopback, 1, Request(IPAddress.Loopback));

        Assert.Equal("127.0.0.1", run.SourceAddress);
        Assert.DoesNotContain(run.Observations, o => o.Text.Contains("无法指定源地址"));
        Assert.Contains(run.Observations, o => o.Text.Contains("绑定源地址 127.0.0.1"));
    }

    [Fact]
    public async Task Icmp_无法绑定时如实标注且不谎报源地址()
    {
        // IPv4 源地址无法用于 IPv6 目标：必须记录限制，且不得把请求的源地址写成实际源地址
        var run = await new IcmpProbe().ExecuteAsync(
            IPAddress.IPv6Loopback, 1, Request(IPAddress.Parse("192.168.10.100")));

        Assert.Null(run.SourceAddress);
        Assert.Contains(run.Observations, o =>
            o.Text.Contains("无法指定源地址") && o.Text.Contains("192.168.10.100"));
    }

    [Fact]
    public async Task Icmp_未指定源地址时不产生源地址观察()
    {
        var run = await new IcmpProbe().ExecuteAsync(IPAddress.Loopback, 1, Request(null));

        Assert.Null(run.SourceAddress);
        Assert.DoesNotContain(run.Observations, o => o.Text.Contains("无法指定源地址"));
    }
}
