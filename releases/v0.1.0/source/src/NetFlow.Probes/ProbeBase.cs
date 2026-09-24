using System.Net;
using System.Net.Sockets;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>探针执行请求。</summary>
public sealed record ProbeRequest
{
    public required ProbeParameters Parameters { get; init; }

    public required RunId RunId { get; init; }

    /// <summary>指定的本机源地址（null = 系统按路由自动选择）。</summary>
    public IPAddress? SourceAddress { get; init; }

    /// <summary>目标解析出的地址（null = 探针自行解析）。</summary>
    public IPAddress? ResolvedTarget { get; init; }

    /// <summary>DNS 服务器（DNS 探针专用：直接向该服务器发查询）。</summary>
    public IPAddress? DnsServer { get; init; }

    public CancellationToken CancellationToken { get; init; }
}

/// <summary>目标名称解析器抽象（便于离线测试与指定 DNS 的初步发现）。</summary>
public interface INameResolver
{
    /// <summary>解析目标名称。失败抛 ProbeNameResolutionException。</summary>
    Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct);
}

/// <summary>名称解析失败异常。探针据此输出 NameResolutionFailed。</summary>
public sealed class ProbeNameResolutionException(string host, Exception inner)
    : Exception($"无法解析目标名称“{host}”", inner)
{
    public string Host { get; } = host;
}

/// <summary>系统默认解析器（System.Net.Dns）。仅用于目标初步发现。</summary>
public sealed class SystemNameResolver : INameResolver
{
    public static readonly SystemNameResolver Instance = new();

    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken ct)
    {
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            return addrs.Length == 0
                ? throw new ProbeNameResolutionException(host,
                    new Exception("解析成功但无地址记录"))
                : addrs;
        }
        catch (ProbeNameResolutionException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new ProbeNameResolutionException(host, ex);
        }
    }
}

/// <summary>探针基类：统一 Run 生命周期、观察记录、异常分类。</summary>
public abstract class ProbeBase
{
    public abstract ProbeType Type { get; }

    /// <summary>探针显示名（中文）。</summary>
    public abstract string DisplayName { get; }

    protected static ProbeRun NewRun(ProbeRequest req) => new()
    {
        RunId = req.RunId,
        Parameters = req.Parameters,
        State = ProbeState.Running,
        StartUtc = DateTimeOffset.UtcNow,
    };

    protected static void FinishRun(ProbeRun run, ProbeState state = ProbeState.Completed)
    {
        run.State = state;
        run.EndUtc = DateTimeOffset.UtcNow;
    }

    /// <summary>把 SocketException 分类为传输层观察（纯函数，可测试）。</summary>
    public static TransportOutcome ClassifySocketError(SocketError error) => error switch
    {
        SocketError.ConnectionRefused => TransportOutcome.Refused,
        SocketError.TimedOut => TransportOutcome.Timeout,
        SocketError.HostUnreachable => TransportOutcome.Unreachable,
        SocketError.NetworkUnreachable => TransportOutcome.Unreachable,
        SocketError.HostNotFound => TransportOutcome.NameResolutionFailed,
        SocketError.ConnectionReset => TransportOutcome.Refused,
        SocketError.NetworkReset => TransportOutcome.Refused,
        SocketError.AccessDenied => TransportOutcome.LocalError,
        SocketError.AddressNotAvailable => TransportOutcome.LocalError,
        _ => TransportOutcome.LocalError,
    };

    /// <summary>是否操作被取消（外部取消，不是超时）。</summary>
    protected static bool IsExternalCancellation(OperationCanceledException ex, CancellationToken ct) =>
        ct.IsCancellationRequested || ex is OperationCanceledException { CancellationToken.IsCancellationRequested: true };
}
