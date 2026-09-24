using System.Net;
using System.Net.Sockets;
using System.Text;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>
/// SSH 探针（设计文档 4.4）：TCP 22 + 版本横幅交换（最小化服务握手）。
/// 不声称登录或授权成功。
/// </summary>
public sealed class SshProbe : TcpHandshakeProbeBase
{
    public override ProbeType Type => ProbeType.Ssh;

    public override string DisplayName => "SSH";

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, int port, ProbeRequest request)
    {
        var run = NewRun(request);
        var timeout = request.Parameters.Timeout;
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        run.AddObservation(Observation.Now($"SSH 探测：{target}:{port}", DisplayName));

        Socket? socket = null;
        try
        {
            socket = await ConnectAsync(target, port, request.SourceAddress, timeout, ct, run, DisplayName)
                .ConfigureAwait(false);
            run.Transport = TransportOutcome.Success;

            // 服务端先行发送版本横幅
            var banner = ToAscii(await ReadUntilAsync(socket, "\n"u8.ToArray(),
                timeout, ct).ConfigureAwait(false)).Trim();
            if (!banner.StartsWith("SSH-"))
            {
                run.Protocol = ProtocolOutcome.ProtocolError;
                run.ProtocolDetail = $"响应不是 SSH 版本横幅：{banner}";
                run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                FinishRun(run);
                return run;
            }

            run.Protocol = ProtocolOutcome.Success;
            run.ProtocolDetail = $"SSH 版本横幅：{banner}。仅握手成功，不代表登录或授权成功。";
            run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName,
                new Dictionary<string, string> { ["banner"] = banner }));

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
