using System.Text.RegularExpressions;

namespace NetFlow.Capture;

/// <summary>实时抓包解析出的一个数据包摘要。</summary>
public sealed record LivePacket(
    string Time, string Direction, string Source, string Destination, string Protocol, string Info, int Length);

/// <summary>
/// 解析 <c>pktmon start --capture --log-mode real-time</c> 的屏幕输出（tcpdump 风格）。
/// 每个包输出两行：头部行（时间、方向、组件…）+ 以制表符开头的详情行。
/// pktmon 会在协议栈各组件重复输出同一个包，这里按“同方向、相同内容、5 毫秒内”去重。
/// 头部行含本地化文字，只依赖其中的 ASCII 片段（时间、Tx/Rx）。
/// </summary>
public sealed partial class PktmonLiveParser
{
    private const long DuplicateWindowTicks = 5 * TimeSpan.TicksPerMillisecond;
    private const int MaxRememberedKeys = 4000;

    [GeneratedRegex(@"^(?<t>\d{2}:\d{2}:\d{2}\.\d+)\s+PktGroupId\b.*?(?<=\s)(?<d>Tx|Rx)(?=\s)")]
    private static partial Regex Header();

    [GeneratedRegex(@"^\t.*?, ethertype (?<et>\S+) \(0x[0-9a-fA-F]+\), length (?<len>\d+): ?(?<rest>.*)$")]
    private static partial Regex Detail();

    [GeneratedRegex(@"^(?<src>\S+) > (?<dst>\S+?): (?<info>.*)$")]
    private static partial Regex IpLine();

    [GeneratedRegex(@"^(?:Request|Reply) who-has (?<who>\S+) tell (?<tell>\S+?),")]
    private static partial Regex ArpRequest();

    [GeneratedRegex(@"^Reply (?<ip>\S+) is-at ")]
    private static partial Regex ArpReply();

    [GeneratedRegex(@"Flags \[(?<f>[^\]]*)\]")]
    private static partial Regex TcpFlags();

    [GeneratedRegex(@"\bwin (?<v>\d+)")]
    private static partial Regex Win();

    [GeneratedRegex(@"\blength (?<v>\d+)")]
    private static partial Regex Len();

    [GeneratedRegex(@"\bseq (?<v>\d+)")]
    private static partial Regex Seq();

    private (string Time, string Direction, long Ticks)? _pendingHeader;
    private readonly Dictionary<string, long> _lastSeen = [];

    /// <summary>喂入一行输出；当一个（去重后的）数据包完整时返回它。</summary>
    public bool TryFeed(string line, out LivePacket? packet)
    {
        packet = null;
        if (line.Length == 0) return false;

        if (line[0] != '\t')
        {
            var h = Header().Match(line);
            _pendingHeader = h.Success
                ? (h.Groups["t"].Value, h.Groups["d"].Value, ParseTicks(h.Groups["t"].Value))
                : null;
            return false;
        }

        if (_pendingHeader is not { } header) return false;
        _pendingHeader = null;

        var d = Detail().Match(line);
        if (!d.Success) return false;

        var rest = d.Groups["rest"].Value;
        var direction = header.Direction;
        var key = direction + "|" + rest;
        if (_lastSeen.TryGetValue(key, out var last) && Math.Abs(header.Ticks - last) <= DuplicateWindowTicks)
        {
            _lastSeen[key] = header.Ticks;
            return false; // 同一个包在其他组件的重复输出
        }
        _lastSeen[key] = header.Ticks;
        if (_lastSeen.Count > MaxRememberedKeys) PruneOld(header.Ticks);

        packet = Build(header.Time, direction, d.Groups["et"].Value, int.Parse(d.Groups["len"].Value), rest);
        return true;
    }

    private void PruneOld(long nowTicks)
    {
        foreach (var k in _lastSeen.Where(kv => nowTicks - kv.Value > DuplicateWindowTicks * 20 || kv.Value > nowTicks)
                     .Select(kv => kv.Key).ToList())
            _lastSeen.Remove(k);
    }

    /// <summary>“13:28:35.952890300” → ticks（100ns，取小数前 7 位）。</summary>
    public static long ParseTicks(string time)
    {
        var parts = time.Split('.');
        var hms = parts[0].Split(':');
        var ticks = ((long.Parse(hms[0]) * 60 + long.Parse(hms[1])) * 60 + long.Parse(hms[2])) * TimeSpan.TicksPerSecond;
        if (parts.Length > 1)
        {
            var frac = parts[1].PadRight(7, '0')[..7];
            ticks += long.Parse(frac);
        }
        return ticks;
    }

    private static LivePacket Build(string time, string dir, string etherType, int length, string rest)
    {
        var dirText = dir == "Tx" ? "发出" : "接收";
        var shortTime = time.Length > 12 ? time[..12] : time;

        var arp = ArpRequest().Match(rest);
        if (arp.Success)
            return new(shortTime, dirText, arp.Groups["tell"].Value, arp.Groups["who"].Value, "ARP",
                $"谁有 {arp.Groups["who"].Value}？告诉 {arp.Groups["tell"].Value}", length);
        var arpReply = ArpReply().Match(rest);
        if (arpReply.Success)
            return new(shortTime, dirText, arpReply.Groups["ip"].Value, "", "ARP", rest, length);

        var ip = IpLine().Match(rest);
        if (!ip.Success)
            return new(shortTime, dirText, "", "", etherType, rest, length);

        var (srcHost, srcPort) = SplitPort(ip.Groups["src"].Value);
        var (dstHost, dstPort) = SplitPort(ip.Groups["dst"].Value);
        var info = ip.Groups["info"].Value;

        string protocol;
        string shown;
        if (info.StartsWith("Flags [", StringComparison.Ordinal))
        {
            protocol = "TCP";
            shown = DescribeTcp(info);
        }
        else if (info.StartsWith("ICMP6", StringComparison.Ordinal))
        {
            protocol = "ICMPv6";
            shown = info;
        }
        else if (info.StartsWith("ICMP", StringComparison.Ordinal))
        {
            protocol = "ICMP";
            shown = info;
        }
        else if (info.StartsWith("UDP", StringComparison.Ordinal))
        {
            protocol = srcPort == 53 || dstPort == 53 ? "DNS" : "UDP";
            shown = info;
        }
        else
        {
            protocol = etherType;
            shown = info;
        }

        return new(shortTime, dirText,
            srcPort > 0 ? $"{srcHost}:{srcPort}" : srcHost,
            dstPort > 0 ? $"{dstHost}:{dstPort}" : dstHost,
            protocol, shown, length);
    }

    /// <summary>
    /// 拆分 tcpdump 风格的 “地址.端口”：IPv4 有 5 段（a.b.c.d.port）、IPv6 以最后一个点分端口；
    /// 无端口（ICMP 等）原样返回。
    /// </summary>
    public static (string Host, int Port) SplitPort(string endpoint)
    {
        if (endpoint.Contains(':')) // IPv6
        {
            var dot = endpoint.LastIndexOf('.');
            if (dot > 0 && int.TryParse(endpoint[(dot + 1)..], out var p6) && !endpoint[..dot].Contains('.'))
                return (endpoint[..dot], p6);
            return (endpoint, 0);
        }
        var parts = endpoint.Split('.');
        if (parts.Length == 5 && int.TryParse(parts[4], out var p4))
            return (string.Join('.', parts[..4]), p4);
        return (endpoint, 0);
    }

    public static string DescribeTcp(string info)
    {
        var flags = TcpFlags().Match(info).Groups["f"].Value;
        var names = flags switch
        {
            "S" => "SYN",
            "S." => "SYN,ACK",
            "." => "ACK",
            "F." => "FIN,ACK",
            "F" => "FIN",
            "R" => "RST",
            "R." => "RST,ACK",
            "P." => "PSH,ACK",
            "" => "无标志",
            _ => flags,
        };
        var parts = new List<string> { $"[{names}]" };
        if (Seq().Match(info) is { Success: true } s) parts.Add($"seq={s.Groups["v"].Value}");
        if (Win().Match(info) is { Success: true } w) parts.Add($"win={w.Groups["v"].Value}");
        if (Len().Match(info) is { Success: true } l) parts.Add($"len={l.Groups["v"].Value}");
        return string.Join(' ', parts);
    }
}
