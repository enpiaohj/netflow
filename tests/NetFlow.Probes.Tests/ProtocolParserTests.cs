using NetFlow.Domain;
using NetFlow.Probes;
using Xunit;

namespace NetFlow.Probes.Tests;

public class ProtocolParserTests
{
    // ---- SSRP（SQL Browser）----

    [Fact]
    public void Ssrp_Parse_FindsNamedInstancePort()
    {
        // serverName;instance;isClustered;version;tcpPort;;
        var text = "FS01;MSSQLSERVER;No;16.0.1000.6;1433;;FS01;SQLEXPRESS;No;16.0.1000.6;54321;;";
        var (name, port, available) = SqlServerProbe.ParseSsrp(text, "SQLEXPRESS");

        Assert.Equal("SQLEXPRESS", name);
        Assert.Equal(54321, port);
        Assert.Equal(2, available.Count);
    }

    [Fact]
    public void Ssrp_Parse_DefaultInstance_ReturnsFirstWhenNoWanted()
    {
        var text = "FS01;MSSQLSERVER;No;16.0.1000.6;1433;;";
        var (name, port, _) = SqlServerProbe.ParseSsrp(text, null);

        Assert.Equal("MSSQLSERVER", name);
        Assert.Equal(1433, port);
    }

    [Fact]
    public void Ssrp_Parse_MissingInstance_ReturnsAvailableList()
    {
        var text = "FS01;MSSQLSERVER;No;16.0.1000.6;1433;;";
        var (name, port, available) = SqlServerProbe.ParseSsrp(text, "NOTTHERE");

        Assert.Null(name);
        Assert.Null(port);
        Assert.Single(available);
    }

    // ---- SMB2 NEGOTIATE ----

    [Fact]
    public void Smb_NegotiateRequest_HasValidNetBiosAndHeader()
    {
        var pkt = SmbProbe.BuildNegotiateRequest();

        // NetBIOS 长度与实际长度一致
        int len = (pkt[0] << 24) | (pkt[1] << 16) | (pkt[2] << 8) | pkt[3];
        Assert.Equal(pkt.Length - 4, len);
        // SMB2 协议标识
        Assert.Equal(0xFE, pkt[4]);
        Assert.Equal((byte)'S', pkt[5]);
        Assert.Equal((byte)'M', pkt[6]);
        Assert.Equal((byte)'B', pkt[7]);
    }

    [Fact]
    public void Smb_NegotiateResponse_ParsesStatusAndDialect()
    {
        var resp = new byte[70];
        // Header Status（偏移 8，小端）
        resp[8] = 0x00; resp[9] = 0x00; resp[10] = 0x00; resp[11] = 0x00;
        // Dialect（偏移 68，小端）3.1.1 = 0x0311
        resp[68] = 0x11; resp[69] = 0x03;

        var result = SmbProbe.ParseNegotiateResponse(resp);

        Assert.Equal(0u, result.NtStatus);
        Assert.Equal(0x0311, result.DialectRevision);
        Assert.Equal("SMB 3.1.1", SmbProbe.DialectText(result.DialectRevision));
    }

    // ---- NTP ----

    [Fact]
    public void Ntp_ParseServerResponse_ExtractsStratumAndTime()
    {
        var pkt = new byte[48];
        pkt[0] = 0x24; // LI=0 VN=4 Mode=4(server)
        pkt[1] = 2;    // stratum 2
        // 传输时间戳：秒 = NTP epoch (2026-01-01 ≈ 3942758400 unix seconds)
        uint seconds = (uint)(1767225600 + 2208988800); // 2026-01-01 UTC 的 NTP 秒
        pkt[40] = (byte)(seconds >> 24);
        pkt[41] = (byte)(seconds >> 16);
        pkt[42] = (byte)(seconds >> 8);
        pkt[43] = (byte)seconds;

        var info = NtpWire.TryParseServerResponse(pkt);

        Assert.NotNull(info);
        Assert.Equal(4, info!.Version);
        Assert.Equal(4, info.Mode);
        Assert.Equal(2, info.Stratum);
        Assert.Equal(2026, info.ServerTimeUtc.Year);
    }

    [Fact]
    public void Ntp_ParseRejectsClientModePacket()
    {
        var pkt = new byte[48];
        pkt[0] = 0x1B; // mode 3 client
        Assert.Null(NtpWire.TryParseServerResponse(pkt));
    }

    // ---- RDP X.224 ----

    [Fact]
    public void Rdp_ConnectionRequest_HasValidTpkt()
    {
        var pkt = RdpProbe.BuildConnectionRequest();

        Assert.Equal(3, pkt[0]); // TPKT version
        Assert.Equal(0, pkt[1]);
        int len = (pkt[2] << 8) | pkt[3];
        Assert.Equal(pkt.Length, len);
        Assert.Equal(0xE0, pkt[5]); // X.224 CR
    }

    [Fact]
    public void Rdp_ConfirmWithNegResponse_ParsesSelectedProtocol()
    {
        // TPKT(4) + X224 CC(7) + RDP_NEG_RSP(type=2,flags=0,len=8,proto=2)
        var data = new byte[11 + 8];
        data[0] = 3;
        data[5] = 0xD0;
        data[11] = 2;  // NEG_RSP
        data[13] = 8;  // length
        data[15] = 2;  // selectedProtocol = CredSSP

        var result = RdpProbe.ParseConfirm(data);

        Assert.Equal((byte)2, result.NegType);
        Assert.Equal((byte)2, result.ProtocolSelected);
        Assert.Equal("CredSSP/NLA", result.SelectedText);
    }

    // ---- TCP/UDP 传输分类 ----

    [Fact]
    public void SocketError_Classification_MatchesAcceptanceMatrix()
    {
        Assert.Equal(TransportOutcome.Refused,
            ProbeBase.ClassifySocketError(System.Net.Sockets.SocketError.ConnectionRefused));
        Assert.Equal(TransportOutcome.Timeout,
            ProbeBase.ClassifySocketError(System.Net.Sockets.SocketError.TimedOut));
        Assert.Equal(TransportOutcome.Unreachable,
            ProbeBase.ClassifySocketError(System.Net.Sockets.SocketError.HostUnreachable));
        Assert.Equal(TransportOutcome.Refused,
            ProbeBase.ClassifySocketError(System.Net.Sockets.SocketError.ConnectionReset));
        Assert.Equal(TransportOutcome.LocalError,
            ProbeBase.ClassifySocketError(System.Net.Sockets.SocketError.AccessDenied));
    }
}
