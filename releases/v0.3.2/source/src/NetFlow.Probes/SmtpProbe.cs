using System.Net;
using System.Net.Sockets;
using System.Text;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>
/// SMTP 探针（设计文档 4.4）：Banner、EHLO、可选 STARTTLS。
/// 不发送邮件、不尝试认证，除非用户主动配置测试。
/// </summary>
public sealed class SmtpProbe : TcpHandshakeProbeBase
{
    public override ProbeType Type => ProbeType.Smtp;

    public override string DisplayName => "SMTP";

    public bool StartTlsEnabled { get; init; }

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, int port, ProbeRequest request)
    {
        var run = NewRun(request);
        var timeout = request.Parameters.Timeout;
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        run.AddObservation(Observation.Now($"SMTP 探测：{target}:{port}", DisplayName));

        Socket? socket = null;
        try
        {
            socket = await ConnectAsync(target, port, request.SourceAddress, timeout, ct, run, DisplayName)
                .ConfigureAwait(false);
            run.Transport = TransportOutcome.Success;

            var deadline = DateTime.UtcNow + timeout;

            // 阶段 1：Banner（期待 220）
            var banner = ToAscii(await ReadUntilAsync(socket, "\r\n"u8.ToArray(),
                deadline - DateTime.UtcNow, ct).ConfigureAwait(false));
            run.AddObservation(Observation.Now($"服务端 Banner：{banner.Trim()}",
                DisplayName,
                new Dictionary<string, string> { ["banner"] = banner.Trim() }));

            if (!banner.StartsWith("220"))
            {
                run.Protocol = ProtocolOutcome.ProtocolError;
                run.ProtocolDetail = $"Banner 非正常就绪响应（期待 220，实际 {banner.Trim()}）";
                FinishRun(run);
                return run;
            }

            // 阶段 2：EHLO（期待 250 多行；其他响应码=协议层失败事实）
            var ehlo = Encoding.ASCII.GetBytes($"EHLO {NetFlowInfo.UserAgent}\r\n");
            await SendAsync(socket, ehlo, ct).ConfigureAwait(false);
            var ehloResp = ToAscii(await ReadUntilAsync(socket, "\r\n"u8.ToArray(),
                deadline - DateTime.UtcNow, ct).ConfigureAwait(false));
            // 多行响应以 "250-..." 连续，读至 "250 ..."（带空格）结束
            while (ehloResp.StartsWith("250-"))
            {
                var more = ToAscii(await ReadUntilAsync(socket, "\r\n"u8.ToArray(),
                    deadline - DateTime.UtcNow, ct).ConfigureAwait(false));
                ehloResp = more;
            }

            if (!ehloResp.StartsWith("250"))
            {
                run.Protocol = ProtocolOutcome.ServiceError;
                run.ProtocolDetail =
                    $"Banner 正常但 EHLO 被拒绝（{ehloResp.Trim()}）。这是 SMTP 服务的明确响应，非网络断开。" +
                    "常见于发件限制策略或需先认证/STARTTLS 的端口。";
                run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                FinishRun(run);
                return run;
            }
            run.AddObservation(Observation.Now($"EHLO 响应：{ehloResp.Trim()}", DisplayName));

            bool tlsAdvertised = ehloResp.Contains("STARTTLS", StringComparison.OrdinalIgnoreCase);
            run.AddObservation(Observation.Now(
                tlsAdvertised ? "服务端支持 STARTTLS" : "服务端未通告 STARTTLS", DisplayName));

            if (StartTlsEnabled && tlsAdvertised)
            {
                await SendAsync(socket, Encoding.ASCII.GetBytes("STARTTLS\r\n"), ct)
                    .ConfigureAwait(false);
                var tlsResp = ToAscii(await ReadUntilAsync(socket, "\r\n"u8.ToArray(),
                    deadline - DateTime.UtcNow, ct).ConfigureAwait(false));
                if (tlsResp.StartsWith("220"))
                {
                    run.AddObservation(Observation.Now(
                        "服务端同意 STARTTLS（220）。TLS 阶段检查见 TLS 探针。", DisplayName));
                    run.ProtocolDetail = $"Banner/EHLO/STARTTLS 协商成功（STARTTLS 已同意）";
                }
                else
                {
                    run.Protocol = ProtocolOutcome.ProtocolError;
                    run.ProtocolDetail = $"STARTTLS 请求被拒绝：{tlsResp.Trim()}";
                    FinishRun(run);
                    return run;
                }
            }

            // 阶段 3：QUIT（礼貌关闭；不发送邮件不认证）
            try
            {
                await SendAsync(socket, Encoding.ASCII.GetBytes("QUIT\r\n"), ct)
                    .ConfigureAwait(false);
            }
            catch (SocketException)
            {
                // 服务端先行关闭不影响结论
            }

            run.Protocol = ProtocolOutcome.Success;
            run.ProtocolDetail ??= $"Banner 与 EHLO 按协议预期响应";
            FinishRun(run);
            return run;
        }
        catch (Exception ex)
        {
            return HandleTransportException(run, ex, timeout, ct, DisplayName);
        }
        finally
        {
            socket?.Dispose();
        }
    }
}
