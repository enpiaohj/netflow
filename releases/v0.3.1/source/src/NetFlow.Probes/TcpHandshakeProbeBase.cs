using System.Net;
using System.Net.Sockets;
using System.Text;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>
/// 基于 TCP 的应用协议握手探针共用设施。
/// 共同原则：端口可连接只证明传输层；协议阶段按协议自身响应判定。
/// </summary>
public abstract class TcpHandshakeProbeBase : ProbeBase
{
    /// <summary>带超时的连接 + 数据收发封装。</summary>
    protected static async Task<Socket> ConnectAsync(
        IPAddress target, int port, IPAddress? source,
        TimeSpan timeout, CancellationToken external, ProbeRun run, string displayName)
    {
        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true,
        };
        if (source is not null)
            socket.Bind(new IPEndPoint(source, 0));

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(external);
        timeoutCts.CancelAfter(timeout);
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            await socket.ConnectAsync(new IPEndPoint(target, port), timeoutCts.Token)
                .ConfigureAwait(false);
            sw.Stop();
            run.Stages = run.Stages.Append(new StageTiming
            {
                Stage = "TCP 连接",
                Duration = sw.Elapsed,
                StartUtc = run.StartUtc,
            }).ToArray();
            run.SourceAddress = (socket.LocalEndPoint as IPEndPoint)?.Address.ToString();
            run.AddObservation(Observation.Now(
                $"TCP 连接成功：{target}:{port}（{(int)sw.Elapsed.TotalMilliseconds} ms）", displayName));
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>读直到出现指定结束标记（如 \r\n）。取消/超时抛 OperationCanceledException。</summary>
    protected static async Task<byte[]> ReadUntilAsync(
        Socket socket, ReadOnlyMemory<byte> delimiter, TimeSpan remaining,
        CancellationToken external, int maxBytes = 8192)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(external);
        cts.CancelAfter(remaining);
        var buffer = new MemoryStream();
        var chunk = new byte[1024];

        while (true)
        {
            var data = buffer.ToArray();
            if (IndexOf(data, delimiter.Span) >= 0) return data;
            if (buffer.Length > maxBytes)
                throw new InvalidOperationException("响应超过长度上限，疑似非目标协议");

            int n = await socket.ReceiveAsync(chunk, cts.Token).ConfigureAwait(false);
            if (n == 0)
                throw new EndOfStreamException("对端在完整响应前关闭连接");
            buffer.Write(chunk, 0, n);
        }
    }

    protected static async Task SendAsync(
        Socket socket, byte[] data, CancellationToken ct) =>
        await socket.SendAsync(data, ct).ConfigureAwait(false);

    protected static int IndexOf(byte[] haystack, ReadOnlySpan<byte> needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
                return i;
        }
        return -1;
    }

    protected static string ToAscii(byte[] data) => Encoding.ASCII.GetString(data);

    /// <summary>统一异常分类处理：把通用传输异常落到 ProbeRun。</summary>
    protected static ProbeRun HandleTransportException(
        ProbeRun run, Exception ex, TimeSpan timeout, CancellationToken ct, string displayName)
    {
        switch (ex)
        {
            case SocketException se:
                run.Transport = ClassifySocketError(se.SocketErrorCode);
                run.ErrorCode = se.SocketErrorCode.ToString();
                run.AddObservation(Observation.Now($"套接字错误：{se.SocketErrorCode}", displayName));
                break;
            case EndOfStreamException:
                run.Transport = TransportOutcome.Refused;
                run.ErrorCode = "CONNECTION_CLOSED";
                run.AddObservation(Observation.Now("对端接受连接后立即关闭（明确反馈）", displayName));
                break;
            case InvalidOperationException:
                run.Transport = TransportOutcome.Success;
                run.Protocol = ProtocolOutcome.ProtocolError;
                run.ErrorCode = "PROTOCOL_MISMATCH";
                run.AddObservation(Observation.Now(ex.Message, displayName));
                break;
            case OperationCanceledException when !ct.IsCancellationRequested:
                run.Transport = run.Transport is TransportOutcome.NotExecuted
                    ? TransportOutcome.Timeout
                    : run.Transport;
                run.Protocol = run.Transport is TransportOutcome.Timeout
                    ? ProtocolOutcome.NotExecuted
                    : ProtocolOutcome.NoResponse;
                run.ErrorCode = "TIMEOUT";
                run.AddObservation(Observation.Now(
                    $"超时：{timeout.TotalSeconds}s 内未完成该阶段", displayName));
                break;
            case OperationCanceledException:
                run.State = ProbeState.Canceled;
                run.EndUtc = DateTimeOffset.UtcNow;
                break;
            default:
                run.Transport = TransportOutcome.LocalError;
                run.ErrorCode = ex.GetType().Name;
                run.AddObservation(Observation.Now($"本地错误：{ex.Message}", displayName));
                break;
        }

        if (run.State != ProbeState.Canceled)
        {
            run.State = run.Transport is TransportOutcome.LocalError
                ? ProbeState.Failed
                : ProbeState.Completed;
            run.EndUtc = DateTimeOffset.UtcNow;
        }
        return run;
    }
}
