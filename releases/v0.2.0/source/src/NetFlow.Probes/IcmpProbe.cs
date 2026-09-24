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

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, int sampleCount, ProbeRequest request)
    {
        var run = NewRun(request);
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        // .NET Ping 不支持绑定源地址：不再把“请求的源地址”写成本次源地址
        NoteSourceNotBindable(run, request, DisplayName, "ICMP 回显", "Windows ICMP 接口限制");

        int replied = 0;
        var rttList = new List<long>();

        for (int i = 0; i < sampleCount; i++)
        {
            ct.ThrowIfCancellationRequested();
            using var ping = new Ping();
            var sw = Stopwatch.StartNew();
            PingReply reply;
            try
            {
                var options = new PingOptions(64, true);
                var buffer = new byte[32];
                reply = await ping.SendPingAsync(target, (int)request.Parameters.Timeout.TotalMilliseconds,
                    buffer, options).ConfigureAwait(false);
            }
            catch (PingException ex)
            {
                run.AddObservation(Observation.Now($"Ping 发送失败：{ex.GetBaseException().Message}", DisplayName));
                run.Transport = TransportOutcome.LocalError;
                FinishRun(run, ProbeState.Failed);
                return run;
            }

            sw.Stop();
            switch (reply.Status)
            {
                case IPStatus.Success:
                    replied++;
                    rttList.Add(reply.RoundtripTime);
                    run.AddObservation(Observation.Now(
                        $"样本 {i + 1}/{sampleCount}：回显应答，RTT {reply.RoundtripTime} ms" +
                        (reply.Address is not null ? $"，来源 {reply.Address}" : ""), DisplayName));
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
        NoteSourceNotBindable(run, request, DisplayName, "路径探测", "Windows ICMP 接口限制");

        for (int ttl = 1; ttl <= maxHops; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            var hopObservations = new List<string>();
            bool reachedTarget = false;
            string? hopAddress = null;

            for (int s = 0; s < samplesPerHop; s++)
            {
                using var ping = new Ping();
                PingReply reply;
                try
                {
                    reply = await ping.SendPingAsync(target,
                        (int)request.Parameters.Timeout.TotalMilliseconds, new byte[32],
                        new PingOptions(ttl, true)).ConfigureAwait(false);
                }
                catch (PingException)
                {
                    hopObservations.Add("探针错误");
                    continue;
                }

                switch (reply.Status)
                {
                    case IPStatus.Success:
                    case IPStatus.TtlExpired:
                        hopAddress ??= reply.Address?.ToString();
                        reachedTarget |= reply.Status == IPStatus.Success;
                        hopObservations.Add($"RTT {reply.RoundtripTime} ms");
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
