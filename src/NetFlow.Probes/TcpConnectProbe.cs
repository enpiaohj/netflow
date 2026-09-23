using System.Net;
using System.Net.Sockets;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>
/// TCP 连接探针（设计文档 4.3）：区分连接成功、明确拒绝、超时、DNS 失败、本机套接字错误。
/// 记录连接耗时与实际连接的目标 IP。TCP 可连接只证明传输层建立。
/// </summary>
public sealed class TcpConnectProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.TcpConnect;

    public override string DisplayName => "TCP 连接";

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, int port, ProbeRequest request)
    {
        var run = NewRun(request);
        var timeout = request.Parameters.Timeout;
        var ct = request.CancellationToken;

        run.ResolvedAddresses = [target.ToString()];
        run.SourceAddress = request.SourceAddress?.ToString();
        run.AddObservation(Observation.Now(
            $"发起 TCP 连接：{target}:{port}" +
            (request.SourceAddress is { } s ? $"（绑定源地址 {s}）" : ""),
            DisplayName));

        var family = target.AddressFamily;
        using var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
        if (request.SourceAddress is { } src)
            socket.Bind(new IPEndPoint(src, 0));

        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout);

            await socket.ConnectAsync(new IPEndPoint(target, port), timeoutCts.Token)
                .ConfigureAwait(false);
            sw.Stop();

            run.Transport = TransportOutcome.Success;
            run.Protocol = ProtocolOutcome.NotExecuted;
            run.SourceAddress = (socket.LocalEndPoint as IPEndPoint)?.Address.ToString();
            run.Stages = [new StageTiming
            {
                Stage = "TCP 三次握手",
                Duration = sw.Elapsed,
                StartUtc = run.StartUtc,
                EndUtc = DateTimeOffset.UtcNow,
            }];
            run.AddObservation(Observation.Now(
                $"连接成功（源端口 {(socket.LocalEndPoint as IPEndPoint)?.Port}，耗时 {(int)sw.Elapsed.TotalMilliseconds} ms）",
                DisplayName));

            FinishRun(run);
            return run;
        }
        catch (SocketException ex)
        {
            sw.Stop();
            run.Transport = ClassifySocketError(ex.SocketErrorCode);
            run.ErrorCode = ex.SocketErrorCode.ToString();
            run.AddObservation(Observation.Now(
                $"连接失败：{ex.SocketErrorCode}（{(int)sw.Elapsed.TotalMilliseconds} ms）", DisplayName));
            FinishRun(run);
            return run;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            run.Transport = TransportOutcome.Timeout;
            run.ErrorCode = "TCP_TIMEOUT";
            run.AddObservation(Observation.Now(
                $"超时：SYN 已发出，{timeout.TotalSeconds}s 内未完成三次握手，也未收到拒绝。", DisplayName));
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
        catch (ObjectDisposedException ex)
        {
            run.Transport = TransportOutcome.LocalError;
            run.ErrorCode = ex.GetType().Name;
            run.AddObservation(Observation.Now($"本地套接字错误：{ex.Message}", DisplayName));
            FinishRun(run, ProbeState.Failed);
            return run;
        }
    }
}
