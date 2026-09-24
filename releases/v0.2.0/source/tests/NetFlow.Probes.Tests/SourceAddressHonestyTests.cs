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
    public async Task Icmp_指定源地址时记录限制且不谎报源地址()
    {
        var run = await new IcmpProbe().ExecuteAsync(
            IPAddress.Loopback, 1, Request(IPAddress.Parse("192.168.10.100")));

        Assert.Null(run.SourceAddress);
        Assert.Contains(run.Observations, o =>
            o.Text.Contains("无法指定源地址") && o.Text.Contains("192.168.10.100"));
    }

    [Fact]
    public async Task Icmp_未指定源地址时不产生源地址限制观察()
    {
        var run = await new IcmpProbe().ExecuteAsync(IPAddress.Loopback, 1, Request(null));

        Assert.DoesNotContain(run.Observations, o => o.Text.Contains("无法指定源地址"));
    }
}
