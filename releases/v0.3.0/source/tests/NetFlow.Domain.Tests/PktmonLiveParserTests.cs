using NetFlow.Capture;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>pktmon 实时模式输出解析（样本取自真实抓包输出）。</summary>
public class PktmonLiveParserTests
{
    private const string Mac = "BC-EC-A0-08-FD-7E > 00-0C-29-F3-A9-D4, ethertype IPv4 (0x0800), length 74";

    private static string Header(string time, string dir, int component = 77) =>
        $"{time} PktGroupId 281474976710663，PktNumber 1，出现 0，方向 {dir} ，类型 Ethernet ，组件 {component}，边缘 1，筛选器 1，OriginalSize 74，LoggedSize 64 ";

    private static List<LivePacket> Parse(params string[] lines)
    {
        var parser = new PktmonLiveParser();
        var list = new List<LivePacket>();
        foreach (var line in lines)
            if (parser.TryFeed(line, out var p)) list.Add(p!);
        return list;
    }

    [Fact]
    public void ICMP_请求与应答_识别方向_无端口只显示IP()
    {
        var packets = Parse(
            Header("13:28:35.952890300", "Tx"),
            $"\t{Mac}: 192.168.10.100 > 192.168.10.11: ICMP echo request, id 1, seq 68, length 40",
            Header("13:28:35.954801200", "Rx", 117),
            "\t00-0C-29-F3-A9-D4 > BC-EC-A0-08-FD-7E, ethertype IPv4 (0x0800), length 74: 192.168.10.11 > 192.168.10.100: ICMP echo reply, id 1, seq 68, length 40");

        Assert.Equal(2, packets.Count);
        Assert.Equal("发出", packets[0].Direction);
        Assert.Equal("192.168.10.100", packets[0].Source);
        Assert.Equal("192.168.10.11", packets[0].Destination);
        Assert.Equal("ICMP", packets[0].Protocol);
        Assert.Contains("echo request", packets[0].Info);
        Assert.Equal("接收", packets[1].Direction);
        Assert.Equal("13:28:35.954", packets[1].Time);
    }

    [Fact]
    public void 同一个包在多个组件重复输出_只保留一条()
    {
        var detail = $"\t{Mac}: 192.168.10.100 > 192.168.10.11: ICMP echo request, id 1, seq 68, length 40";
        var packets = Parse(
            Header("13:28:35.952890300", "Tx", 77), detail,
            Header("13:28:35.952893600", "Tx", 28), detail,
            Header("13:28:35.952895100", "Tx", 29), detail,
            Header("13:28:35.952927300", "Tx", 117), detail);

        Assert.Single(packets);
    }

    [Fact]
    public void 相同内容但间隔超过去重窗口_视为不同的包()
    {
        var detail = $"\t{Mac}: 192.168.10.100 > 192.168.10.11: ICMP echo request, id 1, seq 68, length 40";
        var packets = Parse(
            Header("13:28:35.952890300", "Tx"), detail,
            Header("13:28:36.965966400", "Tx"), detail);

        Assert.Equal(2, packets.Count);
    }

    [Fact]
    public void TCP_握手标志中文化_带端口()
    {
        var packets = Parse(
            Header("13:30:01.100000000", "Tx"),
            $"\t{Mac}: 192.168.10.100.52673 > 192.168.10.11.445: Flags [S], seq 4066593772, win 65535, options [mss 1460,nop,wscale 8,nop,nop,sackOK], length 0",
            Header("13:30:01.101000000", "Rx"),
            $"\t{Mac}: 192.168.10.11.445 > 192.168.10.100.52673: Flags [S.], seq 786895, ack 4066593773, win 65535, options [mss 1460], length 0",
            Header("13:30:01.500000000", "Rx"),
            $"\t{Mac}: 192.168.10.11.445 > 192.168.10.100.52673: Flags [R.], seq 786896, ack 4066593774, win 0, length 0");

        Assert.Equal(3, packets.Count);
        Assert.Equal("TCP", packets[0].Protocol);
        Assert.Equal("192.168.10.100:52673", packets[0].Source);
        Assert.Equal("192.168.10.11:445", packets[0].Destination);
        Assert.Equal("[SYN] seq=4066593772 win=65535 len=0", packets[0].Info);
        Assert.StartsWith("[SYN,ACK]", packets[1].Info);
        Assert.StartsWith("[RST,ACK]", packets[2].Info);
    }

    [Fact]
    public void UDP_53端口识别为DNS_其他为UDP()
    {
        var packets = Parse(
            Header("13:31:00.000000000", "Tx"),
            $"\t{Mac}: 192.168.10.100.62443 > 192.168.10.11.123: UDP, length 48",
            Header("13:31:01.000000000", "Tx"),
            $"\t{Mac}: 192.168.10.100.55555 > 192.168.10.11.53: UDP, length 30");

        Assert.Equal("UDP", packets[0].Protocol);
        Assert.Equal("192.168.10.11:123", packets[0].Destination);
        Assert.Equal("DNS", packets[1].Protocol);
    }

    [Fact]
    public void ARP_请求_提取询问方与被询问IP()
    {
        var packets = Parse(
            Header("13:32:00.000000000", "Rx"),
            "\tff-ff-ff-ff-ff-ff > aa-bb-cc-dd-ee-ff, ethertype ARP (0x0806), length 42: Request who-has 192.168.10.100 tell 192.168.10.1, length 28");

        var p = Assert.Single(packets);
        Assert.Equal("ARP", p.Protocol);
        Assert.Equal("192.168.10.1", p.Source);
        Assert.Equal("192.168.10.100", p.Destination);
    }

    [Theory]
    [InlineData("192.168.10.100.52673", "192.168.10.100", 52673)]
    [InlineData("192.168.10.11", "192.168.10.11", 0)]           // ICMP：无端口
    [InlineData("fe80::1.546", "fe80::1", 546)]
    [InlineData("2001:db8::10", "2001:db8::10", 0)]
    public void SplitPort_IPv4与IPv6(string endpoint, string host, int port)
    {
        Assert.Equal((host, port), PktmonLiveParser.SplitPort(endpoint));
    }

    [Fact]
    public void 无头部的详情行_预热文本_乱码行_都被忽略()
    {
        var packets = Parse(
            "收集的数据:",
            "    数据包计数器，数据包捕获",
            "正在处理...",
            $"\t{Mac}: 192.168.10.100 > 192.168.10.11: ICMP echo request, id 1, seq 1, length 40", // 缺少头部
            "13:28:35.9 乱码头部 没有 PktGroupId",
            $"\t{Mac}: 192.168.10.100 > 192.168.10.11: ICMP echo request, id 1, seq 2, length 40");

        Assert.Empty(packets);
    }

    [Fact]
    public void 头部行本地化文字为GBK被按Latin1读成乱码_仍能解析()
    {
        // 模拟 Latin-1 读到的 GBK 中文（“方向”→ "·½Ïò"）
        var header = "13:28:35.952890300 PktGroupId 281474976710663，PktNumber 1，³öÏÖ 0，·½Ïò Tx ，ÀàÐÍ Ethernet ，×é¼þ 77";
        var packets = Parse(header, $"\t{Mac}: 10.0.0.1 > 10.0.0.2: ICMP echo request, id 1, seq 1, length 40");

        var p = Assert.Single(packets);
        Assert.Equal("发出", p.Direction);
    }

    [Fact]
    public void ParseTicks_纳秒时间取前7位小数()
    {
        Assert.Equal(TimeSpan.FromSeconds(3661).Ticks + 1234567, PktmonLiveParser.ParseTicks("01:01:01.123456789"));
        Assert.Equal(TimeSpan.FromSeconds(5).Ticks, PktmonLiveParser.ParseTicks("00:00:05"));
    }

    [Fact]
    public void 实时模式启动参数_缓冲文件限定在任务目录且限制大小()
    {
        var args = CaptureHostProgram.BuildLiveStartArgs(128, @"C:\work\live-buffer.etl");

        Assert.Contains("real-time", args);
        Assert.Equal(@"C:\work\live-buffer.etl", args[args.ToList().IndexOf("--file-name") + 1]);
        // 未限制时 pktmon 会在工作目录生成最大 512 MB 的默认 PktMon.etl
        Assert.Equal("16", args[args.ToList().IndexOf("--file-size") + 1]);
        Assert.Equal("128", args[args.ToList().IndexOf("--pkt-size") + 1]);
    }

    [Fact]
    public void 采集参数_模式默认record_非法模式被拒绝_旧JSON兼容()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nf-live-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var legacy = CaptureParams.FromJson(
                $$"""{"RunId":"0123456789abcdef","TargetIp":"10.0.0.1","WorkingDirectory":{{System.Text.Json.JsonSerializer.Serialize(dir)}},"StopEventName":"Local\\x"}""");
            Assert.NotNull(legacy);
            Assert.Equal(CaptureParams.RecordMode, legacy!.Mode);
            Assert.Empty(legacy.Validate());

            Assert.Empty((legacy with { Mode = CaptureParams.LiveMode }).Validate());
            Assert.Contains("采集模式非法", string.Join(";", (legacy with { Mode = "x" }).Validate()));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
