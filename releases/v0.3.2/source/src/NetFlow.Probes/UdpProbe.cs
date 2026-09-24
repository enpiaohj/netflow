using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>自定义 UDP 载荷（设计文档 4.3：明确发送目标、编码、期望应答）。</summary>
public sealed record UdpPayload
{
    /// <summary>载荷字节。null 时由 KnownProtocol 自动生成。</summary>
    public byte[]? Bytes { get; init; }

    /// <summary>文本载荷与编码（Bytes 优先）。</summary>
    public string? Text { get; init; }

    public string EncodingName { get; init; } = "utf-8";

    /// <summary>已知协议模板：发送真实协议请求以确认服务响应。</summary>
    public KnownUdpProtocol? KnownProtocol { get; init; }

    public byte[] BuildBytes()
    {
        if (Bytes is { } b) return b;
        if (KnownProtocol == KnownUdpProtocol.Ntp) return NtpWire.BuildClientRequest();
        if (KnownProtocol == KnownUdpProtocol.Dns)
        {
            // 占位：DnsProbe 才能构造正确查询，这里禁止
            throw new InvalidOperationException("DNS 载荷请使用 DnsProbe");
        }
        if (Text is { } t) return Encoding.GetEncoding(EncodingName).GetBytes(t);
        throw new InvalidOperationException("UDP 载荷为空");
    }
}

public enum KnownUdpProtocol
{
    None,
    Ntp,
    Dns,
}

/// <summary>
/// UDP 探针（设计文档 4.3）：发出请求后按响应分类——
/// 收到合法响应=请求应答成功；收到 ICMP 错误=明确网络反馈；仅发送成功/超时=未确认。
/// </summary>
public sealed class UdpProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.UdpDatagram;

    public override string DisplayName => "UDP 数据报";

    public async Task<ProbeRun> ExecuteAsync(
        IPAddress target, int port, UdpPayload payload, ProbeRequest request,
        Func<byte[], bool>? responseValidator = null)
    {
        var run = NewRun(request);
        var timeout = request.Parameters.Timeout;
        var ct = request.CancellationToken;

        run.ResolvedAddresses = [target.ToString()];
        run.SourceAddress = request.SourceAddress?.ToString();

        byte[] bytes;
        try
        {
            bytes = payload.BuildBytes();
        }
        catch (Exception ex)
        {
            run.Transport = TransportOutcome.LocalError;
            run.ErrorCode = "PAYLOAD_BUILD";
            run.AddObservation(Observation.Now($"载荷构造失败：{ex.Message}", DisplayName));
            FinishRun(run, ProbeState.Failed);
            return run;
        }

        var payloadDesc = payload.KnownProtocol switch
        {
            KnownUdpProtocol.Ntp => $"NTP 客户端请求（{bytes.Length} 字节）",
            KnownUdpProtocol.Dns => "DNS 查询（见 DNS 探针）",
            _ => $"{bytes.Length} 字节自定义载荷",
        };
        run.AddObservation(Observation.Now(
            $"向 {target}:{port}/UDP 发送 {payloadDesc}", DisplayName));

        using var udp = new UdpClient(target.AddressFamily);
        if (request.SourceAddress is { } src)
            udp.Client.Bind(new IPEndPoint(src, 0));

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            await udp.SendAsync(bytes, new IPEndPoint(target, port), timeoutCts.Token)
                .ConfigureAwait(false);
            run.AddObservation(Observation.Now(
                $"发送成功（{bytes.Length} 字节，源端口 {(udp.Client.LocalEndPoint as IPEndPoint)?.Port}）",
                DisplayName));
            sw.Stop();
            var sendTiming = sw.Elapsed;

            // 等待应答
            sw.Restart();
            bool resetRetried = false;
            while (true)
            {
                UdpReceiveResult result;
                try
                {
                    result = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                }
                catch (SocketException ex) when (
                    ex.SocketErrorCode is SocketError.ConnectionReset && !resetRetried)
                {
                    // Windows：ICMP 端口不可达以 ConnectionReset 呈现；重收一次以兼容迟到响应
                    resetRetried = true;
                    run.AddObservation(Observation.Now(
                        "收到 ICMP 不可达反馈（目标端口无监听或被过滤设备明确拒绝）", DisplayName));
                    continue;
                }

                var resp = result.Buffer;
                run.AddObservation(Observation.Now(
                    $"收到来自 {result.RemoteEndPoint} 的应答（{resp.Length} 字节，" +
                    $"发送后 {(int)sw.Elapsed.TotalMilliseconds} ms）", DisplayName));

                bool valid = responseValidator?.Invoke(resp) ?? true;
                run.Transport = TransportOutcome.Success;
                run.Stages =
                [
                    new StageTiming { Stage = "UDP 发送", Duration = sendTiming, StartUtc = run.StartUtc },
                    new StageTiming { Stage = "等待应答", Duration = sw.Elapsed },
                ];
                if (valid)
                {
                    run.Protocol = ProtocolOutcome.Success;
                    run.ProtocolDetail =
                        $"收到 {resp.Length} 字节应答" +
                        (responseValidator != null ? "且通过校验" : "");
                }
                else
                {
                    run.Protocol = ProtocolOutcome.ProtocolError;
                    run.ProtocolDetail = "收到应答但内容不符合所选协议预期";
                }
                FinishRun(run);
                return run;
            }
        }
        catch (SocketException ex)
        {
            run.Transport = ClassifySocketError(ex.SocketErrorCode);
            run.ErrorCode = ex.SocketErrorCode.ToString();
            run.AddObservation(Observation.Now($"套接字错误：{ex.SocketErrorCode}", DisplayName));
            FinishRun(run);
            return run;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // 超时：请求已发出，无任何反馈 → 未确认
            run.Transport = TransportOutcome.Success; // 发送已成功
            run.Protocol = ProtocolOutcome.NoResponse;
            run.Stages =
            [
                new StageTiming { Stage = "UDP 发送", Duration = sw.Elapsed, StartUtc = run.StartUtc },
                new StageTiming { Stage = "等待应答", Duration = null },
            ];
            run.ErrorCode = "UDP_NO_RESPONSE";
            run.AddObservation(Observation.Now(
                $"在 {timeout.TotalSeconds}s 等待窗口内未收到任何应答或 ICMP 反馈。服务状态未确认。", DisplayName));
            FinishRun(run);
            return run;
        }
        catch (OperationCanceledException)
        {
            run.State = ProbeState.Canceled;
            run.EndUtc = DateTimeOffset.UtcNow;
            run.AddObservation(Observation.Now("已取消。", DisplayName));
            return run;
        }
    }
}

/// <summary>NTP 报文构建与解析（RFC 5905）。</summary>
public static class NtpWire
{
    public static byte[] BuildClientRequest()
    {
        var pkt = new byte[48];
        // LI=0 VN=4 Mode=3(client)
        pkt[0] = 0x1B;
        return pkt;
    }

    public static NtpServerInfo? TryParseServerResponse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 48) return null;
        byte liVnMode = data[0];
        byte mode = (byte)(liVnMode & 0x07);
        byte version = (byte)((liVnMode >> 3) & 0x07);
        if (mode != 4) return null; // 必须是 server 模式

        byte stratum = data[1];
        sbyte poll = (sbyte)data[2];
        sbyte precision = (sbyte)data[3];
        var rootDelay = Fixed16_16ToSeconds(data.Slice(4, 4));
        var transmitSeconds = BinaryPrimitives.ReadUInt32BigEndian(data[40..]);
        var transmitFraction = BinaryPrimitives.ReadUInt32BigEndian(data[44..]);

        return new NtpServerInfo
        {
            Version = version,
            Mode = mode,
            Stratum = stratum,
            PollIntervalSeconds = poll >= 0 ? 1 << poll : 1d / (1 << -poll),
            PrecisionSeconds = Math.Pow(2, precision),
            RootDelaySeconds = rootDelay,
            ServerTimeUtc = NtpTimestampToUtc(transmitSeconds, transmitFraction),
        };
    }

    private static double Fixed16_16ToSeconds(ReadOnlySpan<byte> b) =>
        BinaryPrimitives.ReadUInt32BigEndian(b) / 65536d;

    public static DateTimeOffset NtpTimestampToUtc(uint seconds, uint fraction)
    {
        const long ntpEpochOffset = 2208988800;
        long unixSeconds = (long)seconds - ntpEpochOffset;
        double frac = fraction / 4294967296d;
        return DateTimeOffset.FromUnixTimeMilliseconds(
            unixSeconds * 1000 + (long)(frac * 1000));
    }
}

public sealed record NtpServerInfo
{
    public required byte Version { get; init; }
    public required byte Mode { get; init; }
    public required byte Stratum { get; init; }
    public required double PollIntervalSeconds { get; init; }
    public required double PrecisionSeconds { get; init; }
    public required double RootDelaySeconds { get; init; }
    public required DateTimeOffset ServerTimeUtc { get; init; }
}
