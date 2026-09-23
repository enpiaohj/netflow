using System.Net;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>
/// NTP 探针（设计文档 4.4）：合规客户端请求、校验模式/长度/来源合法性、计算往返与时间偏差。
/// 不将单次偏差视为权威校时审计。
/// </summary>
public sealed class NtpProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.Ntp;

    public override string DisplayName => "NTP 时间同步";

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, ProbeRequest request)
    {
        var run = NewRun(request);
        var timeout = request.Parameters.Timeout;
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        run.SourceAddress = request.SourceAddress?.ToString();

        var request_ = NtpWire.BuildClientRequest();
        run.AddObservation(Observation.Now(
            $"向 {target}:123/UDP 发送 NTP 客户端请求（{request_.Length} 字节）", DisplayName));

        using var udp = new System.Net.Sockets.UdpClient(target.AddressFamily);
        if (request.SourceAddress is { } src)
            udp.Client.Bind(new System.Net.IPEndPoint(src, 0));

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);

        var t0 = DateTimeOffset.UtcNow; // 发送时刻（用于偏差估算）
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            await udp.SendAsync(request_, new System.Net.IPEndPoint(target, 123), timeoutCts.Token)
                .ConfigureAwait(false);
            var sendSw = sw.Elapsed;

            bool resetRetried = false;
            while (true)
            {
                System.Net.Sockets.UdpReceiveResult result;
                try
                {
                    result = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                }
                catch (System.Net.Sockets.SocketException ex) when (
                    ex.SocketErrorCode is System.Net.Sockets.SocketError.ConnectionReset
                        && !resetRetried)
                {
                    resetRetried = true;
                    run.AddObservation(Observation.Now(
                        "收到 ICMP 不可达反馈（NTP 服务未监听或被明确拒绝）", DisplayName));
                    continue;
                }

                var recvUtc = DateTimeOffset.UtcNow;
                sw.Stop();

                var info = NtpWire.TryParseServerResponse(result.Buffer);
                if (info is null)
                {
                    run.Transport = TransportOutcome.Success;
                    run.Protocol = ProtocolOutcome.ProtocolError;
                    run.ProtocolDetail =
                        $"收到 {result.Buffer.Length} 字节响应，但不是合法的 NTP server 报文（模式/长度不符）";
                    run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                    FinishRun(run);
                    return run;
                }

                // 估算偏差 = 服务器时间 −（t0 + 往返/2），单次采样仅供参考
                var offset = info.ServerTimeUtc - (t0 + (recvUtc - t0) / 2);
                run.Transport = TransportOutcome.Success;
                run.Protocol = ProtocolOutcome.Success;
                run.Stages =
                [
                    new StageTiming { Stage = "NTP 请求", Duration = sendSw, StartUtc = run.StartUtc },
                    new StageTiming { Stage = "等待响应", Duration = sw.Elapsed },
                ];
                run.AddObservation(Observation.Now(
                    $"收到合法 NTP server 响应：版本 {info.Version}，stratum {info.Stratum}，" +
                    $"往返 {(int)sw.Elapsed.TotalMilliseconds} ms", DisplayName,
                    attributes: new Dictionary<string, string>
                    {
                        ["stratum"] = info.Stratum.ToString(),
                        ["rttMs"] = ((int)sw.Elapsed.TotalMilliseconds).ToString(),
                    }));
                run.AddObservation(Observation.Now(
                    $"服务器时间 {info.ServerTimeUtc:yyyy-MM-dd HH:mm:ss.fff} UTC，" +
                    $"估算偏差 {offset.TotalMilliseconds:+0;-0} ms（单次采样，非权威校时审计）",
                    DisplayName));

                FinishRun(run);
                return run;
            }
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            run.Transport = ClassifySocketError(ex.SocketErrorCode);
            run.ErrorCode = ex.SocketErrorCode.ToString();
            run.AddObservation(Observation.Now($"套接字错误：{ex.SocketErrorCode}", DisplayName));
            FinishRun(run);
            return run;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            run.Transport = TransportOutcome.Success;
            run.Protocol = ProtocolOutcome.NoResponse;
            run.ErrorCode = "NTP_NO_RESPONSE";
            run.AddObservation(Observation.Now(
                $"NTP 请求已发出；{timeout.TotalSeconds}s 采集窗口内未见匹配应答。状态未确认。", DisplayName));
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
