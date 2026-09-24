using System.Buffers.Binary;
using System.Net;

namespace NetFlow.Probes.DnsProtocol;

/// <summary>DNS 记录类型（RFC 1035 及扩展）。</summary>
public enum DnsRecordType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    ANY = 255,
}

/// <summary>DNS 响应码。</summary>
public enum DnsRcode : ushort
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3, // NXDOMAIN
    NotImplemented = 4,
    Refused = 5,
}

/// <summary>DNS 查询类型（递归开关等由头部 RD 位表达）。</summary>
internal static class BigEndianWriterExtensions
{
    public static void WriteBigEndian(this BinaryWriter w, ushort v)
    {
        w.Write((byte)(v >> 8));
        w.Write((byte)(v & 0xFF));
    }
}

public static class DnsWire
{
    /// <summary>构建标准查询报文。transactionId 随机生成。</summary>
    public static (byte[] Message, ushort TransactionId) BuildQuery(
        string name, DnsRecordType type, bool recursionDesired = true)
    {
        ushort id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var ms = new MemoryStream(64);
        var w = new BinaryWriter(ms);

        w.WriteBigEndian(id);
        // QR=0, Opcode=0, AA=0, TC=0, RD=recursion | RA=0 Z=0 RCODE=0
        w.WriteBigEndian((ushort)(recursionDesired ? 0x0100 : 0x0000));
        w.WriteBigEndian((ushort)1); // QDCOUNT
        w.WriteBigEndian((ushort)0); // ANCOUNT
        w.WriteBigEndian((ushort)0); // NSCOUNT
        w.WriteBigEndian((ushort)0); // ARCOUNT

        WriteName(w, name);
        w.WriteBigEndian((ushort)type);
        w.WriteBigEndian((ushort)1); // IN

        w.Flush();
        return (ms.ToArray(), id);
    }

    /// <summary>解析响应报文。数据不足/格式错抛 DnsWireFormatException。</summary>
    public static DnsResponse Parse(ReadOnlySpan<byte> data, ushort expectedTransactionId)
    {
        if (data.Length < 12)
            throw new DnsWireFormatException("响应不足 12 字节头部");

        ushort id = BinaryPrimitives.ReadUInt16BigEndian(data);
        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        ushort qd = BinaryPrimitives.ReadUInt16BigEndian(data[4..]);
        ushort an = BinaryPrimitives.ReadUInt16BigEndian(data[6..]);
        ushort ns = BinaryPrimitives.ReadUInt16BigEndian(data[8..]);
        ushort ar = BinaryPrimitives.ReadUInt16BigEndian(data[10..]);

        bool isResponse = (flags & 0x8000) != 0;
        byte opcode = (byte)((flags >> 11) & 0xF);
        bool authoritative = (flags & 0x0400) != 0;
        bool truncated = (flags & 0x0200) != 0;
        bool recursionAvailable = (flags & 0x0080) != 0;
        var rcode = (DnsRcode)(flags & 0xF);

        if (!isResponse)
            throw new DnsWireFormatException("响应 QR 位为 0，不是响应报文");
        if (id != expectedTransactionId)
            throw new DnsWireFormatException("事务 ID 不匹配（已按 RFC 建议丢弃该报文）");

        int pos = 12;
        var questions = new List<DnsQuestion>(qd);
        for (int i = 0; i < qd; i++)
        {
            var name = ReadName(data, ref pos);
            if (pos + 4 > data.Length) throw new DnsWireFormatException("Question 段不完整");
            var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
            pos += 4;
            questions.Add(new DnsQuestion(name, type));
        }

        var answers = new List<DnsRecord>(an);
        pos = ReadRecords(data, pos, an, answers);
        pos = ReadRecords(data, pos, ns, answers); // 权威段与附加段同构解析，标记来源
        pos = ReadRecords(data, pos, ar, answers);

        return new DnsResponse
        {
            TransactionId = id,
            Opcode = opcode,
            Authoritative = authoritative,
            Truncated = truncated,
            RecursionAvailable = recursionAvailable,
            Rcode = rcode,
            Questions = questions,
            Answers = answers,
        };
    }

    private static int ReadRecords(
        ReadOnlySpan<byte> data, int pos, ushort count, List<DnsRecord> into)
    {
        for (int i = 0; i < count; i++)
        {
            var name = ReadName(data, ref pos);
            if (pos + 10 > data.Length) throw new DnsWireFormatException("资源记录不完整");
            var type = (DnsRecordType)BinaryPrimitives.ReadUInt16BigEndian(data[pos..]);
            //class = data[pos+2..pos+4]
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(data[(pos + 4)..]);
            ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(data[(pos + 8)..]);
            pos += 10;
            if (pos + rdLength > data.Length) throw new DnsWireFormatException("RDATA 越界");

            var rdata = data.Slice(pos, rdLength);
            into.Add(ParseRdata(name, type, ttl, rdata, data));
            pos += rdLength;
        }

        return pos;
    }

    private static DnsRecord ParseRdata(
        string name, DnsRecordType type, uint ttl, ReadOnlySpan<byte> rdata,
        ReadOnlySpan<byte> fullMessage)
    {
        switch (type)
        {
            case DnsRecordType.A when rdata.Length == 4:
                return new DnsRecord(name, type, ttl, [new IPAddress(rdata).ToString()]);
            case DnsRecordType.AAAA when rdata.Length == 16:
                return new DnsRecord(name, type, ttl, [new IPAddress(rdata).ToString()]);
            case DnsRecordType.CNAME or DnsRecordType.NS or DnsRecordType.PTR:
            {
                // rdata 是 fullMessage 的尾部切片；域名（含压缩指针）必须按全报文绝对偏移解析
                int p = fullMessage.Length - rdata.Length;
                return new DnsRecord(name, type, ttl, [ReadName(fullMessage, ref p)]);
            }
            case DnsRecordType.MX when rdata.Length >= 3:
            {
                ushort pref = BinaryPrimitives.ReadUInt16BigEndian(rdata);
                int p = fullMessage.Length - rdata.Length + 2;
                return new DnsRecord(name, type, ttl,
                    [$"{pref} {ReadName(fullMessage, ref p)}"]);
            }
            case DnsRecordType.TXT:
            {
                var texts = new List<string>();
                int p = 0;
                while (p < rdata.Length)
                {
                    byte len = rdata[p++];
                    if (p + len > rdata.Length) break;
                    texts.Add(System.Text.Encoding.UTF8.GetString(rdata.Slice(p, len)));
                    p += len;
                }
                return new DnsRecord(name, type, ttl, texts);
            }
            case DnsRecordType.SRV when rdata.Length >= 7:
            {
                ushort priority = BinaryPrimitives.ReadUInt16BigEndian(rdata);
                ushort weight = BinaryPrimitives.ReadUInt16BigEndian(rdata[2..]);
                ushort port = BinaryPrimitives.ReadUInt16BigEndian(rdata[4..]);
                int p = fullMessage.Length - rdata.Length + 6;
                var target = ReadName(fullMessage, ref p);
                return new DnsRecord(name, type, ttl,
                    [$"{priority} {weight} {port} {target}"]);
            }
            case DnsRecordType.SOA when rdata.Length >= 22:
            {
                int rdataStart = fullMessage.Length - rdata.Length;
                int p = rdataStart;
                string mname = ReadName(fullMessage, ref p);
                string rname = ReadName(fullMessage, ref p);
                int rel = p - rdataStart;
                if (rel + 4 > rdata.Length) throw new DnsWireFormatException("SOA RDATA 不完整");
                return new DnsRecord(name, type, ttl,
                    [$"{mname} {rname} (serial={BinaryPrimitives.ReadUInt32BigEndian(rdata[rel..])})"]);
            }
            default:
                return new DnsRecord(name, type, ttl,
                    [Convert.ToHexString(rdata)]);
        }
    }

    public static void WriteName(BinaryWriter w, string name)
    {
        if (string.IsNullOrEmpty(name) || name == ".")
        {
            w.Write((byte)0);
            return;
        }

        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            if (label.Length == 0) continue;
            if (label.Length > 63)
                throw new DnsWireFormatException("DNS 标签超长（>63 字节）");
            w.Write((byte)label.Length);
            var bytes = System.Text.Encoding.UTF8.GetBytes(label);
            w.Write(bytes);
        }
        w.Write((byte)0);
    }

    /// <summary>读取（可能压缩的）域名。pos 必须是 fullMessage 的绝对偏移。</summary>
    internal static string ReadName(ReadOnlySpan<byte> data, ref int pos)
    {
        var sb = new System.Text.StringBuilder();
        int jumps = 0;
        int? nextPos = null;
        int cur = pos;

        while (true)
        {
            if (cur >= data.Length) throw new DnsWireFormatException("域名越界");
            byte len = data[cur];
            if (len == 0)
            {
                cur++;
                break;
            }

            switch (len & 0xC0)
            {
                case 0xC0:
                {
                    if (cur + 1 >= data.Length) throw new DnsWireFormatException("压缩指针不完整");
                    int pointer = ((len & 0x3F) << 8) | data[cur + 1];
                    // RFC 1035：压缩指针必须指向报文中更早的位置；
                    // 向前（或自指）指针只出现在构造的恶意报文中
                    if (pointer >= cur)
                        throw new DnsWireFormatException("压缩指针方向非法（指向后文）");
                    nextPos ??= cur + 2;
                    jumps++;
                    if (jumps > 32) throw new DnsWireFormatException("压缩指针循环");
                    cur = pointer;
                    break;
                }
                case 0:
                {
                    cur++;
                    if (cur + len > data.Length) throw new DnsWireFormatException("标签越界");
                    if (sb.Length > 0) sb.Append('.');
                    sb.Append(System.Text.Encoding.UTF8.GetString(data.Slice(cur, len)));
                    cur += len;
                    break;
                }
                default:
                    throw new DnsWireFormatException("非法域名标签类型");
            }
        }

        pos = nextPos ?? cur;
        return sb.ToString();
    }
}

public sealed class DnsWireFormatException(string message) : Exception(message);

public sealed record DnsQuestion(string Name, DnsRecordType Type);

public sealed record DnsRecord(string Name, DnsRecordType Type, uint Ttl, IReadOnlyList<string> Values)
{
    public string ValuesJoined => string.Join("; ", Values);
}

public sealed record DnsResponse
{
    public required ushort TransactionId { get; init; }
    public byte Opcode { get; init; }
    public bool Authoritative { get; init; }
    public bool Truncated { get; init; }
    public bool RecursionAvailable { get; init; }
    public required DnsRcode Rcode { get; init; }
    public IReadOnlyList<DnsQuestion> Questions { get; init; } = [];
    public IReadOnlyList<DnsRecord> Answers { get; init; } = [];

    /// <summary>答案区中的地址记录。</summary>
    public IReadOnlyList<string> Addresses =>
        Answers
            .Where(r => r.Type is DnsRecordType.A or DnsRecordType.AAAA)
            .SelectMany(r => r.Values)
            .ToArray();

    public static string RcodeText(DnsRcode rcode) => rcode switch
    {
        DnsRcode.NoError => "NOERROR",
        DnsRcode.FormatError => "FORMERR",
        DnsRcode.ServerFailure => "SERVFAIL",
        DnsRcode.NameError => "NXDOMAIN",
        DnsRcode.NotImplemented => "NOTIMP",
        DnsRcode.Refused => "REFUSED",
        _ => $"RCODE{(int)rcode}",
    };
}
