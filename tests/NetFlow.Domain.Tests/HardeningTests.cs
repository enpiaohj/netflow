using System.Buffers.Binary;
using NetFlow.Capture;
using NetFlow.Domain;
using NetFlow.Probes;
using NetFlow.Probes.DnsProtocol;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>安全与稳定性回归：恶意报文防护、流式解析、写入约束。</summary>
public class HardeningTests
{
    // ---- DNS 恶意压缩指针 ----

    [Fact]
    public void DnsWire_ForwardCompressionPointer_IsRejected()
    {
        // 构造答案名中的指针指向"后文"（非 RFC 行为，仅见于构造报文）
        var (_, txId) = DnsWire.BuildQuery("a.example.com", DnsRecordType.A);
        var resp = new byte[]
        {
            (byte)(txId >> 8), (byte)(txId & 0xFF),
            0x81, 0x80,
            0, 1, 0, 1, 0, 0, 0, 0,
        };
        var ms = new MemoryStream();
        ms.Write(resp);
        DnsWire.WriteName(new BinaryWriter(ms), "a.example.com");
        ms.Write(new byte[] { 0, 1, 0, 1 }); // QTYPE/CLASS
        // 答案名：压缩指针 0xC000 + 偏移 0x30=48（当前写入位置之后，非法）
        ms.Write(new byte[] { 0xC0, 0x30 });
        ms.Write(new byte[] { 0, 1, 0, 1 }); // TYPE/CLASS
        ms.Write(new byte[] { 0, 0, 0, 60 }); // TTL
        ms.Write(new byte[] { 0, 4, 1, 2, 3, 4 }); // RDLENGTH/RDATA

        Assert.ThrowsAny<DnsWireFormatException>(() => DnsWire.Parse(ms.ToArray(), txId));
    }

    // ---- PCAPNG 流式解析（合成报文）----

    [Fact]
    public void Pcapng_SyntheticFile_ParsesTcpSyn()
    {
        var path = BuildSyntheticPcapng();
        try
        {
            var analysis = PcapngAnalyzer.Analyze(path);

            var packet = Assert.Single(analysis.Packets);
            Assert.Equal("TCP", packet.Protocol);
            Assert.Equal("SYN", packet.Info);
            Assert.Equal("192.168.10.100", packet.SourceIp);
            Assert.Equal("192.168.10.11", packet.DestinationIp);
            Assert.Equal(445, packet.DestinationPort);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Pcapng_CorruptTailLength_StopsConservatively()
    {
        var path = BuildSyntheticPcapng();
        try
        {
            // 破坏 SHB 尾部长度字段（偏移 24–27）→ 解析必须保守终止且不抛出
            var data = File.ReadAllBytes(path);
            data[24] ^= 0xFF;
            File.WriteAllBytes(path, data);

            var analysis = PcapngAnalyzer.Analyze(path);
            Assert.Empty(analysis.Packets);
        }
        finally
        {
            File.Delete(path);
        }
    }

    /// <summary>构造最小合法 PCAPNG：SHB（LE）+ IDB（Ethernet）+ 一个 TCP SYN 的 EPB。</summary>
    private static string BuildSyntheticPcapng()
    {
        var path = Path.Combine(Path.GetTempPath(), $"nf-{Guid.NewGuid():N}.pcapng");
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);

        // SHB: type=0A0D0D0A, len=28, bom=1A2B3C4D, ver=1.0, len=-1
        w.Write(0x0A0D0D0A);
        w.Write((uint)28);
        w.Write(0x1A2B3C4D);
        w.Write((uint)1); w.Write((uint)0);
        w.Write(unchecked((uint)-1));
        w.Write((uint)28);

        // IDB: type=1, len=20, linktype=1(EN10MB), reserved=0
        w.Write((uint)1);
        w.Write((uint)20);
        w.Write((ushort)1);
        w.Write((ushort)0);
        w.Write((uint)0xFFFFFFFF); // snaplen
        w.Write((uint)20);

        // Ethernet+IPv4+TCP SYN（14+20+20 = 54 字节）
        var frame = new byte[54];
        // Eth: 目的 MAC 6 + 源 MAC 6 + Ethertype 0x0800
        frame[12] = 0x08; frame[13] = 0x00;
        // IPv4
        frame[14] = 0x45; // v4, ihl=20
        frame[14 + 9] = 6; // TCP
        frame[14 + 12] = 192; frame[14 + 13] = 168; frame[14 + 14] = 10; frame[14 + 15] = 100;
        frame[14 + 16] = 192; frame[14 + 17] = 168; frame[14 + 18] = 10; frame[14 + 19] = 11;
        // TCP
        int tcp = 14 + 20;
        frame[tcp] = 0xC3; frame[tcp + 1] = 0x50; // src 50000
        frame[tcp + 2] = 0x01; frame[tcp + 3] = 0xBD; // dst 445
        frame[tcp + 13] = 0x02; // SYN

        // EPB: type=6, len=8 + body(20 + captured) + pad + 4
        // body = IfId(4)+TsHigh(4)+TsLow(4)+CapturedLen(4)+OriginalLen(4) + 帧数据
        uint captured = 54;
        uint bodyLen = 20 + captured; // 74
        uint pad = (4 - bodyLen % 4) % 4; // 2
        uint total = 8 + bodyLen + pad + 4; // 88
        w.Write((uint)6);
        w.Write(total);
        w.Write((uint)0);          // ifId
        w.Write((uint)0x00000001); // tsHigh
        w.Write((uint)0x23456789); // tsLow
        w.Write(captured);
        w.Write(captured);
        w.Write(frame);
        for (int i = 0; i < pad; i++) w.Write((byte)0);
        w.Write(total);

        File.WriteAllBytes(path, ms.ToArray());
        return path;
    }

    // ---- CaptureHost 参数约束 ----

    [Fact]
    public void CaptureParams_RejectsParamsFileOutsideWorkingDirectory()
    {
        var workDir = Path.Combine(Path.GetTempPath(), $"nf-work-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDir);
        try
        {
            var outside = Path.Combine(Path.GetTempPath(), "evil-params.json");
            var parameters = new CaptureParams
            {
                RunId = "0123456789abcdef",
                TargetIp = "192.168.10.11",
                WorkingDirectory = workDir,
                StopEventName = "Local\\NetFlowCapture-test",
            };

            var errors = parameters.Validate(outside);
            Assert.Contains(errors, e => e.Contains("参数文件必须位于工作目录内"));

            var inside = Path.Combine(workDir, "capture-params.json");
            Assert.Empty(parameters.Validate(inside));
        }
        finally
        {
            Directory.Delete(workDir, recursive: true);
        }
    }

    [Fact]
    public void CaptureParams_RejectsBadTargetIp()
    {
        var workDir = Path.Combine(Path.GetTempPath(), $"nf-work-{Guid.NewGuid():N}");
        Directory.CreateDirectory(workDir);
        try
        {
            var parameters = new CaptureParams
            {
                RunId = "0123456789abcdef",
                TargetIp = "not-an-ip; rm -rf",
                WorkingDirectory = workDir,
                StopEventName = "Local\\test",
            };
            var errors = parameters.Validate(Path.Combine(workDir, "p.json"));
            Assert.Contains(errors, e => e.Contains("TargetIp"));
        }
        finally
        {
            Directory.Delete(workDir, recursive: true);
        }
    }
}
