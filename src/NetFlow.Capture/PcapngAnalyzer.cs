using System.Buffers.Binary;
using System.Net;

namespace NetFlow.Capture;

/// <summary>PCAPNG 解析出的数据包摘要。</summary>
public sealed record ParsedPacket
{
    public required ulong TimestampUs { get; init; }
    public required byte[] Data { get; init; }
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required string Protocol { get; init; }
    public int SourcePort { get; init; }
    public int DestinationPort { get; init; }
    public required string Info { get; init; }
}

/// <summary>会话级分析结果。</summary>
public sealed record SessionAnalysis
{
    public required IReadOnlyList<ParsedPacket> Packets { get; init; }
    public required IReadOnlyList<string> Findings { get; init; }
    public int TcpSyn => Packets.Count(p => p.Info == "SYN");
    public int TcpRst => Packets.Count(p => p.Info == "RST");
    public int RetransCandidates => Packets.Count(p => p.Info.StartsWith("重传候选"));
    public int DnsQueries => Packets.Count(p => p.Protocol == "DNS" && p.Info.StartsWith("查询"));
    public int DnsResponses => Packets.Count(p => p.Protocol == "DNS" && p.Info.StartsWith("响应"));
}

/// <summary>
/// 最小 PCAPNG 解析与会话分析（设计文档 4.5 分析范围）：
/// TCP SYN/SYN-ACK/RST/FIN、重传候选、DNS 请求应答、UDP 配对、
/// TLS ClientHello、ICMP 错误。按时间线输出。
/// 解析为流式：逐块读取文件，内存占用与单包大小相关而与文件大小无关；
/// 单包超过上限（65535 字节，以太网 MTU 上限的多倍）按损坏文件保守终止。
/// </summary>
public static class PcapngAnalyzer
{
    private const int MaxPacketBytes = 65535 + 256;

    public static SessionAnalysis Analyze(string pcapngPath) =>
        Analyze(pcapngPath, maxPackets: int.MaxValue);

    public static SessionAnalysis Analyze(string pcapngPath, int maxPackets)
    {
        var packets = Parse(pcapngPath, maxPackets);
        var findings = new List<string>();
        MarkRetransmissions(packets);

        int synNoReply = CountSynWithoutSynAck(packets);
        if (synNoReply > 0)
            findings.Add($"发现 {synNoReply} 个 TCP SYN 未见匹配 SYN-ACK（服务无响应候选，需结合时间窗核对）");
        int rst = packets.Count(p => p.Info == "RST");
        if (rst > 0)
            findings.Add($"发现 {rst} 个 TCP RST（明确拒绝/复位反馈）");
        int udpNoReply = CountUdpWithoutReply(packets);
        if (udpNoReply > 0)
            findings.Add($"发现 {udpNoReply} 个 UDP 请求未见匹配应答（未确认）");
        int retrans = packets.Count(p => p.Info.StartsWith("重传候选"));
        if (retrans > 0)
            findings.Add($"发现 {retrans} 个 TCP 重传候选（可用原始包核对）");
        int icmp = packets.Count(p => p.Protocol == "ICMP");
        if (icmp > 0)
            findings.Add($"发现 {icmp} 个 ICMP 报文（含错误类反馈时用于交叉核对）");

        return new SessionAnalysis
        {
            Packets = packets,
            Findings = findings,
        };
    }

    /// <summary>
    /// PCAPNG 块遍历（SHB/IDB/EPB，按 SHB 字节序修正）。流式读取：
    /// 先读 8 字节块头（类型+长度），再读块体与尾部长度，坏块保守终止。
    /// </summary>
    public static List<ParsedPacket> Parse(string path, int maxPackets = int.MaxValue)
    {
        var packets = new List<ParsedPacket>();
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 64 * 1024, FileOptions.SequentialScan);
        using var reader = new BinaryReader(stream);
        ushort linkType = 1; // 默认 Ethernet
        bool littleEndian = true;

        while (packets.Count < maxPackets)
        {
            // 块头：type(4) + totalLength(4)
            int read;
            var head = new byte[8];
            try
            {
                ReadFull(reader, head);
            }
            catch (EndOfStreamException)
            {
                break; // 正常结束
            }
            uint blockType = ReadU32(head, 0, littleEndian);
            uint blockLen = ReadU32(head, 4, littleEndian);

            // 结构校验：最小 12 字节（头+尾长度），4 字节对齐，不得越出文件
            if (blockLen < 12 || blockLen % 4 != 0)
                break;
            try
            {
                if (stream.Position - 8 + blockLen > stream.Length)
                    break;
            }
            catch (IOException)
            {
                break;
            }

            var bodyLen = (int)(blockLen - 12);
            var body = new byte[bodyLen];
            try
            {
                ReadFull(reader, body);
            }
            catch (EndOfStreamException)
            {
                break;
            }
            var tail = new byte[4];
            try
            {
                ReadFull(reader, tail);
            }
            catch (EndOfStreamException)
            {
                break;
            }
            if (ReadU32(tail, 0, littleEndian) != blockLen)
                break; // 尾部长度与头不一致：文件损坏，保守终止

            switch (blockType)
            {
                case 0x0A0D0D0A: // SHB
                {
                    if (bodyLen < 4) break;
                    // 块结构：type(4)+totalLen(4)+BOM(4)+...，body 从 BOM 开始
                    uint endianMarker = ReadU32(body, 0, littleEndian);
                    if (endianMarker == 0x1A2B3C4D) littleEndian = true;
                    else if (endianMarker == 0x4D3C2B1A) littleEndian = false;
                    break;
                }
                case 0x00000001: // IDB
                {
                    if (bodyLen < 4) break;
                    // IDB: LinkType(2) + Reserved(2)
                    linkType = ReadU16(body, 0, littleEndian);
                    break;
                }
                case 0x00000006: // EPB
                {
                    if (bodyLen < 20) break;
                    // EPB: IfId(4) TsHigh(4) TsLow(4) CapturedLen(4) OriginalLen(4) PacketData...
                    ulong tsHigh = ReadU32(body, 4, littleEndian);
                    ulong tsLow = ReadU32(body, 8, littleEndian);
                    ulong timestamp = (tsHigh << 32) | tsLow;
                    uint capturedLen = ReadU32(body, 12, littleEndian);
                    if (capturedLen == 0 || capturedLen > (uint)(bodyLen - 20) ||
                        capturedLen > MaxPacketBytes)
                        break; // 坏包：跳过该块（非整文件终止）
                    var packetData = new byte[capturedLen];
                    Array.Copy(body, 20, packetData, 0, capturedLen);
                    var parsed = ParseEthernet(packetData, timestamp, linkType);
                    if (parsed is not null)
                        packets.Add(parsed);
                    break;
                }
            }
        }
        return packets;
    }

    private static void ReadFull(BinaryReader reader, byte[] buffer)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = reader.Read(buffer, read, buffer.Length - read);
            if (n == 0) throw new EndOfStreamException();
            read += n;
        }
    }

    private static ParsedPacket? ParseEthernet(byte[] pkt, ulong tsUs, ushort linkType)
    {
        if (linkType != 1 || pkt.Length < 34) return null;
        int ethertype = (pkt[12] << 8) | pkt[13];
        int l3 = 14;

        string protocol;
        string srcIp, dstIp;
        int srcPort = 0, dstPort = 0;
        string info = "";
        int l4Offset;

        if (ethertype == 0x0800 && pkt.Length >= l3 + 20) // IPv4
        {
            int ihl = (pkt[l3] & 0x0F) * 4;
            if (ihl < 20 || pkt.Length < l3 + ihl) return null;
            byte proto = pkt[l3 + 9];
            srcIp = new IPAddress(pkt[(l3 + 12)..(l3 + 16)]).ToString();
            dstIp = new IPAddress(pkt[(l3 + 16)..(l3 + 20)]).ToString();
            l4Offset = l3 + ihl;
            (protocol, srcPort, dstPort, info) = ParseL4(pkt, l4Offset, proto);
        }
        else if (ethertype == 0x86DD && pkt.Length >= l3 + 40) // IPv6
        {
            byte nextHeader = pkt[l3 + 6];
            srcIp = new IPAddress(pkt[(l3 + 8)..(l3 + 24)]).ToString();
            dstIp = new IPAddress(pkt[(l3 + 24)..(l3 + 40)]).ToString();
            l4Offset = l3 + 40;
            (protocol, srcPort, dstPort, info) = ParseL4(pkt, l4Offset, nextHeader);
        }
        else
        {
            return null;
        }

        return new ParsedPacket
        {
            TimestampUs = tsUs,
            Data = pkt,
            SourceIp = srcIp,
            DestinationIp = dstIp,
            Protocol = protocol,
            SourcePort = srcPort,
            DestinationPort = dstPort,
            Info = info,
        };
    }

    private static (string Protocol, int SrcPort, int DstPort, string Info) ParseL4(
        byte[] pkt, int offset, byte protoNumber)
    {
        switch (protoNumber)
        {
            case 6: // TCP
            {
                if (pkt.Length < offset + 20) return ("TCP", 0, 0, "");
                int srcPort = (pkt[offset] << 8) | pkt[offset + 1];
                int dstPort = (pkt[offset + 2] << 8) | pkt[offset + 3];
                int dataOffset = ((pkt[offset + 12] >> 4) & 0xF) * 4;
                byte flags = pkt[offset + 13];
                string info =
                    (flags & 0x02) != 0 && (flags & 0x10) == 0 ? "SYN" :
                    (flags & 0x12) == 0x12 ? "SYN-ACK" :
                    (flags & 0x04) != 0 ? "RST" :
                    (flags & 0x01) != 0 ? "FIN" : "ACK/数据";
                if (info == "ACK/数据" && dstPort == 443 && IsTlsClientHello(pkt, offset + dataOffset))
                    info = "TLS ClientHello";
                return ("TCP", srcPort, dstPort, info);
            }
            case 17: // UDP
            {
                if (pkt.Length < offset + 8) return ("UDP", 0, 0, "");
                int srcPort = (pkt[offset] << 8) | pkt[offset + 1];
                int dstPort = (pkt[offset + 2] << 8) | pkt[offset + 3];
                string proto;
                string info;
                if (srcPort == 53 || dstPort == 53)
                {
                    bool isResponse = pkt.Length > offset + 8 + 2 &&
                        (pkt[offset + 8 + 2] & 0x80) != 0;
                    proto = "DNS";
                    info = isResponse ? "响应" : "查询";
                }
                else if (srcPort == 123 || dstPort == 123)
                {
                    proto = "NTP";
                    info = "NTP 报文";
                }
                else if (srcPort == 1434 || dstPort == 1434)
                {
                    proto = "SSRP";
                    info = "SQL Browser";
                }
                else
                {
                    proto = "UDP";
                    info = "UDP";
                }
                return (proto, srcPort, dstPort, info);
            }
            case 1: // ICMP
                string icmpInfo = pkt.Length > offset + 1
                    ? $"ICMP type={pkt[offset]} code={pkt[offset + 1]}"
                    : "ICMP";
                return ("ICMP", 0, 0, icmpInfo);
            default:
                return ($"IP-{protoNumber}", 0, 0, "");
        }
    }

    private static bool IsTlsClientHello(byte[] pkt, int tlsStart) =>
        tlsStart + 6 <= pkt.Length &&
        pkt[tlsStart] == 0x16 &&          // Handshake
        pkt[tlsStart + 5] == 0x01;        // ClientHello

    private static void MarkRetransmissions(List<ParsedPacket> packets)
    {
        // 相同流（源/目的 IP+端口+方向）、相同序号范围、时间靠后 → 重传候选
        var seen = new Dictionary<string, (uint Seq, int Index)>();
        for (int i = 0; i < packets.Count; i++)
        {
            var p = packets[i];
            if (p.Protocol != "TCP") continue;
            var seq = ReadTcpSeq(p.Data, out var ok);
            if (!ok) continue;
            var key = $"{p.SourceIp}:{p.SourcePort}>{p.DestinationIp}:{p.DestinationPort}";
            if (seen.TryGetValue(key, out var prev) && prev.Seq == seq)
            {
                packets[i] = p with { Info = $"重传候选（与第 {prev.Index + 1} 包同序号）" };
            }
            else
            {
                seen[key] = (seq, i);
            }
        }
    }

    private static uint ReadTcpSeq(byte[] pkt, out bool ok)
    {
        ok = false;
        if (pkt.Length < 14 + 20) return 0;
        int l3 = 14;
        int ihl = (pkt[l3] & 0x0F) * 4;
        int l4 = l3 + ihl;
        if (pkt.Length < l4 + 8) return 0;
        ok = true;
        return (uint)((pkt[l4 + 4] << 24) | (pkt[l4 + 5] << 16) | (pkt[l4 + 6] << 8) | pkt[l4 + 7]);
    }

    private static int CountSynWithoutSynAck(List<ParsedPacket> packets)
    {
        int count = 0;
        foreach (var syn in packets.Where(p => p.Info == "SYN"))
        {
            bool answered = packets.Any(p => p.Info == "SYN-ACK" &&
                p.SourceIp == syn.DestinationIp && p.DestinationIp == syn.SourceIp &&
                p.SourcePort == syn.DestinationPort && p.DestinationPort == syn.SourcePort &&
                p.TimestampUs >= syn.TimestampUs);
            if (!answered) count++;
        }
        return count;
    }

    private static int CountUdpWithoutReply(List<ParsedPacket> packets)
    {
        int count = 0;
        foreach (var req in packets.Where(p =>
            p.Protocol is "UDP" or "NTP" or "SSRP" &&
            !p.Info.Contains("响应")))
        {
            if (req.Protocol != "UDP") continue;
            bool answered = packets.Any(p =>
                p.Protocol == "UDP" &&
                p.SourceIp == req.DestinationIp && p.DestinationIp == req.SourceIp &&
                p.SourcePort == req.DestinationPort && p.DestinationPort == req.SourcePort &&
                p.TimestampUs >= req.TimestampUs);
            if (!answered) count++;
        }
        return count;
    }

    private static uint ReadU32(byte[] d, int pos, bool le) =>
        le ? BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(pos))
           : BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(pos));

    private static ushort ReadU16(byte[] d, int pos, bool le) =>
        le ? BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(pos))
           : BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(pos));
}
