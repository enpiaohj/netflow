using NetFlow.Probes;
using NetFlow.Probes.DnsProtocol;
using Xunit;

namespace NetFlow.Probes.Tests;

public class DnsWireTests
{
    [Fact]
    public void BuildQuery_HasValidHeaderAndQuestion()
    {
        var (msg, id) = DnsWire.BuildQuery("dc01.corp.example.com", DnsRecordType.A);

        // ID
        Assert.Equal(id, (ushort)((msg[0] << 8) | msg[1]));
        // RD 位
        Assert.Equal(0x01, msg[2]);
        // QDCOUNT = 1
        Assert.Equal(1, (msg[4] << 8) | msg[5]);
        // 尾部为 IN (0x0001)
        Assert.Equal(0, msg[^2]);
        Assert.Equal(1, msg[^1]);
    }

    [Fact]
    public void Parse_SimpleAResponse_ReturnsAddress()
    {
        var (query, txId) = DnsWire.BuildQuery("mail.example.com", DnsRecordType.A);
        var resp = BuildMinimalResponse(txId, "mail.example.com", DnsRecordType.A,
            rdata: [192, 0, 2, 10], ttl: 300);

        var parsed = DnsWire.Parse(resp, txId);

        Assert.Equal(DnsRcode.NoError, parsed.Rcode);
        Assert.False(parsed.Truncated);
        var addr = Assert.Single(parsed.Addresses);
        Assert.Equal("192.0.2.10", addr);
        Assert.Equal(300u, parsed.Answers[0].Ttl);
    }

    [Fact]
    public void Parse_CompressedCname_InCompressedPointer()
    {
        // 构造带压缩指针的响应：答案名用指针指向问题区
        var (query, txId) = DnsWire.BuildQuery("ad.example.com", DnsRecordType.A);
        var resp = BuildMinimalResponse(txId, "ad.example.com", DnsRecordType.CNAME,
            rdata: [0xC0, 0x0C], ttl: 60, compressedAnswerName: true);

        var parsed = DnsWire.Parse(resp, txId);

        Assert.Equal(DnsRcode.NoError, parsed.Rcode);
        var record = Assert.Single(parsed.Answers);
        Assert.Equal(DnsRecordType.CNAME, record.Type);
        Assert.Equal("ad.example.com", record.Name);
    }

    [Fact]
    public void Parse_Nxdomain_SeparatesServiceAliveFromBusinessFailure()
    {
        var (_, txId) = DnsWire.BuildQuery("missing.example.com", DnsRecordType.A);
        // 头部：QR=1 RD=1 RA=1 RCODE=3
        var resp = new byte[]
        {
            (byte)(txId >> 8), (byte)(txId & 0xFF),
            0x81, 0x83, // QR=1 RD=1 RCODE=3
            0, 1, 0, 0, 0, 0, 0, 0,
        };
        // 问题区
        var ms = new MemoryStream();
        ms.Write(resp);
        DnsWire.WriteName(new BinaryWriter(ms), "missing.example.com");
        ms.Write(new byte[] { 0, 1, 0, 1 });

        var parsed = DnsWire.Parse(ms.ToArray(), txId);

        Assert.Equal(DnsRcode.NameError, parsed.Rcode);
        Assert.Empty(parsed.Addresses);
    }

    [Fact]
    public void Parse_WrongTransactionId_Throws()
    {
        var (_, txId) = DnsWire.BuildQuery("a.example.com", DnsRecordType.A);
        var resp = BuildMinimalResponse((ushort)(txId + 1), "a.example.com",
            DnsRecordType.A, [1, 2, 3, 4], 60);

        Assert.Throws<DnsWireFormatException>(() => DnsWire.Parse(resp, txId));
    }

    [Fact]
    public void Parse_TruncationFlag_IsVisible()
    {
        var (_, txId) = DnsWire.BuildQuery("big.example.com", DnsRecordType.TXT);
        var resp = BuildMinimalResponse(txId, "big.example.com", DnsRecordType.TXT,
            rdata: [3, (byte)'a', (byte)'b', (byte)'c'], ttl: 30, truncated: true);

        var parsed = DnsWire.Parse(resp, txId);
        Assert.True(parsed.Truncated);
    }

    [Fact]
    public void Parse_SrvRecord_ExtractsPriorityWeightPortTarget()
    {
        var (_, txId) = DnsWire.BuildQuery("_ldap._tcp.dc._msdcs.example.com", DnsRecordType.SRV);
        // 目标名 "dc01.example.com"
        var target = new MemoryStream();
        DnsWire.WriteName(new BinaryWriter(target), "dc01.example.com");
        var targetBytes = target.ToArray();
        var rdata = new byte[6 + targetBytes.Length];
        rdata[0] = 0; rdata[1] = 100;                 // priority 100
        rdata[2] = 0; rdata[3] = 1;                   // weight 1
        rdata[4] = 0x01; rdata[5] = 0x85;             // port 389 (0x0185)
        targetBytes.CopyTo(rdata, 6);

        var resp = BuildMinimalResponse(txId, "_ldap._tcp.dc._msdcs.example.com",
            DnsRecordType.SRV, rdata, 600);

        var parsed = DnsWire.Parse(resp, txId);
        var record = Assert.Single(parsed.Answers);
        Assert.Contains("100 1 389 dc01.example.com", record.ValuesJoined);
    }

    /// <summary>构造最小合法响应报文（全部多字节字段按网络序）。</summary>
    private static byte[] BuildMinimalResponse(
        ushort txId, string qname, DnsRecordType qtype,
        byte[] rdata, uint ttl,
        bool truncated = false, bool compressedAnswerName = false)
    {
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);

        byte hi = (byte)(txId >> 8);
        byte lo = (byte)(txId & 0xFF);
        // flags 高字节：QR=1 RD=1（+TC 位 0x02）
        byte flagsHi = (byte)(truncated ? 0x83 : 0x81);
        w.Write(hi); w.Write(lo);
        w.Write(flagsHi); w.Write((byte)0x00);
        WriteU16(w, 1);   // QDCOUNT
        WriteU16(w, 1);   // ANCOUNT
        WriteU16(w, 0);
        WriteU16(w, 0);

        DnsWire.WriteName(w, qname);
        WriteU16(w, (ushort)qtype);
        WriteU16(w, 1);   // IN

        // 答案：名字可用压缩指针 0xC00C（指向偏移 12 的问题名）
        if (compressedAnswerName)
        {
            w.Write((byte)0xC0); w.Write((byte)0x0C);
        }
        else
        {
            DnsWire.WriteName(w, qname);
        }
        WriteU16(w, (ushort)qtype);
        WriteU16(w, 1);   // class IN
        w.Write((byte)(ttl >> 24)); w.Write((byte)(ttl >> 16));
        w.Write((byte)(ttl >> 8)); w.Write((byte)ttl);
        WriteU16(w, (ushort)rdata.Length);
        w.Write(rdata);

        w.Flush();
        return ms.ToArray();
    }

    private static void WriteU16(BinaryWriter w, ushort v)
    {
        w.Write((byte)(v >> 8));
        w.Write((byte)(v & 0xFF));
    }
}
