using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>
/// ICMP 探针：目标回显与 TTL 递增路径探测（设计文档 4.3）。
/// 中间跳无回复且终点可达时显示"此跳未回复"，不据此定性丢包。
/// </summary>
public sealed class IcmpProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.IcmpPing;

    public override string DisplayName => "ICMP Ping";

    /// <summary>
    /// 发送一次回显。指定了 IPv4 源地址且目标为 IPv4 时走 IcmpSendEcho2Ex 真正绑定源地址；
    /// 否则用 .NET Ping（无法绑定，由调用方标注限制）。
    /// </summary>
    private static async Task<(IPStatus Status, IPAddress? From, long RttMs)> SendOnceAsync(
        IPAddress target, byte ttl, ProbeRequest request)
    {
        var timeoutMs = (int)request.Parameters.Timeout.TotalMilliseconds;
        var payload = new byte[32];
        if (request.SourceAddress is { AddressFamily: System.Net.Sockets.AddressFamily.InterNetwork } source &&
            target.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return await Task.Run(() => IcmpEchoV4.Send(source, target, timeoutMs, ttl, payload))
                .ConfigureAwait(false);
        }

        using var ping = new Ping();
        var reply = await ping.SendPingAsync(target, timeoutMs, payload, new PingOptions(ttl, true))
            .ConfigureAwait(false);
        return (reply.Status, reply.Address, reply.RoundtripTime);
    }

    /// <summary>本次请求能否真正绑定源地址（IPv4 源 + IPv4 目标）。</summary>
    private static bool CanBindSource(IPAddress target, ProbeRequest request) =>
        request.SourceAddress is { AddressFamily: System.Net.Sockets.AddressFamily.InterNetwork } &&
        target.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;

    /// <summary>登记源地址：可绑定则记录实际源地址，否则如实标注限制且不写源地址。</summary>
    private void RegisterSource(ProbeRun run, IPAddress target, ProbeRequest request, string scope)
    {
        if (request.SourceAddress is null) return;
        if (CanBindSource(target, request))
        {
            run.SourceAddress = request.SourceAddress.ToString();
            run.AddObservation(Observation.Now(
                $"{scope}绑定源地址 {request.SourceAddress}（IcmpSendEcho2Ex）", DisplayName));
        }
        else
        {
            NoteSourceNotBindable(run, request, DisplayName, scope, "仅支持 IPv4 源地址访问 IPv4 目标");
        }
    }

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, int sampleCount, ProbeRequest request)
    {
        var run = NewRun(request);
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        RegisterSource(run, target, request, "ICMP 回显");

        int replied = 0;
        var rttList = new List<long>();

        for (int i = 0; i < sampleCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            (IPStatus Status, IPAddress? From, long RttMs) reply;
            try
            {
                reply = await SendOnceAsync(target, 64, request).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is PingException or System.ComponentModel.Win32Exception)
            {
                run.AddObservation(Observation.Now($"Ping 发送失败：{ex.GetBaseException().Message}", DisplayName));
                run.Transport = TransportOutcome.LocalError;
                FinishRun(run, ProbeState.Failed);
                return run;
            }

            switch (reply.Status)
            {
                case IPStatus.Success:
                    replied++;
                    rttList.Add(reply.RttMs);
                    run.AddObservation(Observation.Now(
                        $"样本 {i + 1}/{sampleCount}：回显应答，RTT {reply.RttMs} ms" +
                        (reply.From is not null ? $"，来源 {reply.From}" : ""), DisplayName));
                    break;
                case IPStatus.TimedOut:
                    run.AddObservation(Observation.Now(
                        $"样本 {i + 1}/{sampleCount}：时限内未收到回显应答（未确认，不归因）", DisplayName));
                    break;
                default:
                    run.AddObservation(Observation.Now(
                        $"样本 {i + 1}/{sampleCount}：{reply.Status}", DisplayName));
                    break;
            }
        }

        run.Transport = replied > 0 ? TransportOutcome.Success : TransportOutcome.Timeout;
        run.Protocol = ProtocolOutcome.NotExecuted;
        if (replied > 0)
        {
            run.Stages = [new StageTiming
            {
                Stage = $"ICMP {sampleCount} 样本",
                Duration = run.Elapsed,
                StartUtc = run.StartUtc,
                EndUtc = DateTimeOffset.UtcNow,
            }];
        }

        FinishRun(run);
        return run;
    }

    /// <summary>路径探测（TTL 递增）。每跳多个样本；中间跳无回复记录"此跳未回复"。</summary>
    public async Task<ProbeRun> TraceRouteAsync(
        IPAddress target, int maxHops, int samplesPerHop, ProbeRequest request)
    {
        var run = NewRun(request);
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        RegisterSource(run, target, request, "路径探测");

        for (int ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            var hopObservations = new List<string>();
            bool reachedTarget = false;
            string? hopAddress = null;

            for (int s = 0; s < samplesPerHop; s++)
            {
                (IPStatus Status, IPAddress? From, long RttMs) reply;
                try
                {
                    reply = await SendOnceAsync(target, (byte)ttl, request).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is PingException or System.ComponentModel.Win32Exception)
                {
                    hopObservations.Add("探针错误");
                    continue;
                }

                switch (reply.Status)
                {
                    case IPStatus.Success:
                    case IPStatus.TtlExpired:
                        hopAddress ??= reply.From?.ToString();
                        reachedTarget |= reply.Status == IPStatus.Success;
                        hopObservations.Add($"RTT {reply.RttMs} ms");
                        break;
                    case IPStatus.TimedOut:
                        hopObservations.Add("未回复");
                        break;
                    default:
                        hopObservations.Add(reply.Status.ToString());
                        break;
                }
            }

            int replies = hopObservations.Count(o => o.StartsWith("RTT"));
            var noReply = hopObservations.Count(o => o == "未回复");
            string text = hopAddress is null
                ? $"跳 {ttl}：{noReply}/{samplesPerHop} 样本未回复（此跳未回复，不据此定性路径中断）"
                : $"跳 {ttl}：{hopAddress}，回复 {replies}/{samplesPerHop}";

            run.AddObservation(Observation.Now(text, DisplayName,
                attributes: new Dictionary<string, string>
                {
                    ["ttl"] = ttl.ToString(),
                    ["address"] = hopAddress ?? "",
                }));

            if (reachedTarget)
            {
                run.Transport = TransportOutcome.Success;
                break;
            }

            if (ttl == maxHops)
                run.Transport = TransportOutcome.Timeout;
        }

        FinishRun(run);
        return run;
    }
}
