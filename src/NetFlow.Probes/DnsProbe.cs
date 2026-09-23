using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using NetFlow.Domain;
using NetFlow.Probes.DnsProtocol;

namespace NetFlow.Probes;

/// <summary>
/// DNS 探针：向指定 DNS 服务器发送真实查询报文（UDP，截断时 TCP 重试）。
/// 设计文档 4.2：RCODE、答案、TTL、CNAME 链、权威位、截断标识分别呈现；
/// NXDOMAIN 属于"收到有效响应、业务查询失败"。
/// </summary>
public sealed class DnsProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.Dns;

    public override string DisplayName => "DNS 解析";

    /// <summary>执行一次向指定服务器的查询。</summary>
    public async Task<ProbeRun> ExecuteAsync(
        IPAddress dnsServer,
        string queryName,
        DnsRecordType queryType,
        ProbeRequest request,
        bool useTcp = false,
        bool recursionDesired = true,
        CancellationToken ct = default)
    {
        var run = NewRun(request);
        run.SourceAddress = request.SourceAddress?.ToString();

        var (message, txId) = DnsWire.BuildQuery(queryName, queryType, recursionDesired);
        run.AddObservation(Observation.Now(
            $"向 {dnsServer} 发送 {queryType} 查询：{queryName}（{(useTcp ? "TCP" : "UDP")}，事务 ID 0x{txId:X4}）",
            DisplayName,
            attributes: new Dictionary<string, string>
            {
                ["dnsServer"] = dnsServer.ToString(),
                ["query"] = queryName,
                ["type"] = queryType.ToString(),
            }));

        var timeout = request.Parameters.Timeout;
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var response = useTcp
                ? await QueryTcpAsync(dnsServer, message, txId, timeout, request.SourceAddress, ct)
                    .ConfigureAwait(false)
                : await QueryUdpAsync(dnsServer, message, txId, timeout, request.SourceAddress, ct)
                    .ConfigureAwait(false);
            sw.Stop();

            run.Stages = [new StageTiming
            {
                Stage = useTcp ? "DNS TCP 查询" : "DNS UDP 查询",
                Duration = sw.Elapsed,
                StartUtc = run.StartUtc,
                EndUtc = DateTimeOffset.UtcNow,
            }];

            run.Transport = TransportOutcome.Success;
            run.AddObservation(Observation.Now(
                $"收到响应：{DnsResponse.RcodeText(response.Rcode)}，答案 {response.Answers.Count} 条" +
                (response.Authoritative ? "，权威应答" : "") +
                (response.Truncated ? "，响应被截断（TC=1）" : ""),
                DisplayName,
                attributes: new Dictionary<string, string> { ["rcode"] = DnsResponse.RcodeText(response.Rcode) }));

            // 协议层判定：收到合法响应 = DNS 服务可响应；业务结果按 RCODE 区分
            switch (response.Rcode)
            {
                case DnsRcode.NoError:
                    run.Protocol = ProtocolOutcome.Success;
                    foreach (var rec in response.Answers)
                        run.AddObservation(Observation.Now(
                            $"{rec.Type} 记录：{rec.Name} → {rec.ValuesJoined}（TTL {rec.Ttl}s）", DisplayName));
                    break;
                case DnsRcode.NameError:
                    // NXDOMAIN：服务可响应、该查询业务失败
                    run.Protocol = ProtocolOutcome.ServiceError;
                    run.ProtocolDetail = "NXDOMAIN（名称不存在）。DNS 服务已正常应答，该查询的业务结果为失败。";
                    run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                    break;
                case DnsRcode.ServerFailure:
                    run.Protocol = ProtocolOutcome.ServiceError;
                    run.ProtocolDetail = "SERVFAIL（服务器内部失败）。DNS 服务已应答但未能完成解析。";
                    run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                    break;
                case DnsRcode.Refused:
                    run.Protocol = ProtocolOutcome.ServiceError;
                    run.ProtocolDetail = "REFUSED（服务器拒绝该查询）。";
                    run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                    break;
                default:
                    run.Protocol = ProtocolOutcome.ProtocolError;
                    run.ProtocolDetail = $"异常响应码 {DnsResponse.RcodeText(response.Rcode)}。";
                    run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                    break;
            }

            if (response.Truncated && !useTcp)
            {
                run.AddObservation(Observation.Now(
                    "UDP 响应被截断（TC=1）。标准行为是改用 TCP 重试。", DisplayName));
            }

            FinishRun(run);
            return run;
        }
        catch (DnsWireFormatException ex)
        {
            run.Transport = TransportOutcome.Success;
            run.Protocol = ProtocolOutcome.ProtocolError;
            run.ProtocolDetail = ex.Message;
            run.ErrorCode = "DNS_WIRE_FORMAT";
            run.AddObservation(Observation.Now($"收到无法解析的报文：{ex.Message}", DisplayName));
            FinishRun(run);
            return run;
        }
        catch (SocketException ex)
        {
            run.Transport = ClassifySocketError(ex.SocketErrorCode);
            run.ErrorCode = ex.SocketErrorCode.ToString();
            run.AddObservation(Observation.Now($"套接字错误：{ex.SocketErrorCode}", DisplayName));
            FinishRun(run, run.Transport is TransportOutcome.Timeout ? ProbeState.Completed : ProbeState.Failed);
            return run;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // 内部超时
            run.Transport = TransportOutcome.Timeout;
            run.Protocol = ProtocolOutcome.NoResponse;
            run.ErrorCode = "DNS_TIMEOUT";
            run.AddObservation(Observation.Now(
                $"超时：{(useTcp ? "TCP" : "UDP")} 查询在 {timeout.TotalSeconds}s 内未收到响应。", DisplayName));
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
        catch (Exception ex)
        {
            run.Transport = TransportOutcome.LocalError;
            run.ErrorCode = ex.GetType().Name;
            run.AddObservation(Observation.Now($"本地错误：{ex.Message}", DisplayName));
            FinishRun(run, ProbeState.Failed);
            return run;
        }
    }

    /// <summary>UDP 查询：发送后等待；校验事务 ID；ICMP 不可达以 SocketException 呈现。</summary>
    private static async Task<DnsResponse> QueryUdpAsync(
        IPAddress server, byte[] query, ushort txId, TimeSpan timeout,
        IPAddress? source, CancellationToken ct)
    {
        using var udp = new UdpClient();
        udp.Client.ReceiveTimeout = (int)timeout.TotalMilliseconds;

        if (source is not null)
        {
            udp.Client.Bind(new IPEndPoint(source, 0));
        }

        // 若取消源在等待期间触发，ReceiveAsync 需要能被唤醒
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);

        await udp.SendAsync(query, new IPEndPoint(server, 53), timeoutCts.Token).ConfigureAwait(false);

        // Windows 行为：收到 ICMP 端口不可达时，挂起的 ReceiveAsync 抛 ConnectionReset。
        // 允许一次重收，避免真实响应在 ICMP 错误之后到达时被误判为拒绝。
        bool resetRetried = false;
        while (true)
        {
            byte[] data;
            try
            {
                var result = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                data = result.Buffer;
            }
            catch (SocketException ex) when (
                ex.SocketErrorCode is SocketError.ConnectionReset && !resetRetried)
            {
                resetRetried = true;
                continue;
            }

            // 事务 ID 不匹配的报文（迟到响应等）按 RFC 建议丢弃，继续等
            if (data.Length >= 2 && BinaryPrimitives.ReadUInt16BigEndian(data) != txId)
                continue;

            return DnsWire.Parse(data, txId);
        }
    }

    /// <summary>TCP 查询：2 字节长度前缀 + 报文（RFC 1035 4.2.2）。</summary>
    private static async Task<DnsResponse> QueryTcpAsync(
        IPAddress server, byte[] query, ushort txId, TimeSpan timeout,
        IPAddress? source, CancellationToken ct)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);

        using var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        if (source is not null)
            client.Bind(new IPEndPoint(source, 0));

        await client.ConnectAsync(new IPEndPoint(server, 53), timeoutCts.Token).ConfigureAwait(false);

        var payload = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(payload, (ushort)query.Length);
        query.CopyTo(payload.AsSpan(2));
        await client.SendAsync(payload, timeoutCts.Token).ConfigureAwait(false);

        var lengthBuf = new byte[2];
        await ReadFullAsync(client, lengthBuf, timeoutCts.Token).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadUInt16BigEndian(lengthBuf);

        var buf = new byte[length];
        await ReadFullAsync(client, buf, timeoutCts.Token).ConfigureAwait(false);
        return DnsWire.Parse(buf, txId);
    }

    private static async Task ReadFullAsync(Socket s, byte[] buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n = await s.ReceiveAsync(buf.AsMemory(read), ct).ConfigureAwait(false);
            if (n == 0) throw new DnsWireFormatException("对端在响应完整前关闭连接");
            read += n;
        }
    }
}
