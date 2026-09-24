using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetFlow.Domain;
using NetFlow.Probes;
using NetFlow.Probes.DnsProtocol;

namespace NetFlow.Application;

/// <summary>
/// 把场景步骤翻译为探针调用。参数字典支持占位符 {target}/{domain}。
/// 每个探针的"未实现阶段"必须输出未支持/未检查，不用 TCP 结果冒充协议验证。
/// </summary>
public sealed class ProbeStepExecutor
{
    private readonly DiagnosisRequest _request;
    private readonly INameResolver _resolver;

    public ProbeStepExecutor(DiagnosisRequest request, INameResolver resolver)
    {
        _request = request;
        _resolver = resolver;
    }

    public async Task<ProbeRun> ExecuteStepAsync(
        ScenarioStep step, IPAddress target, RunId runId, CancellationToken ct)
    {
        var parameters = new ProbeParameters
        {
            ProbeType = step.ProbeType,
            RequestedTarget = _request.RequestedTarget,
            Port = ParsePort(step),
            Timeout = _request.Timeout,
            Extra = ExpandParameters(step),
        };
        var probeRequest = new ProbeRequest
        {
            Parameters = parameters,
            RunId = runId,
            SourceAddress = _request.SourceAddress,
            CancellationToken = ct,
        };

        return step.ProbeType switch
        {
            ProbeType.TcpConnect => await new TcpConnectProbe()
                .ExecuteAsync(target, parameters.Port ?? 80, probeRequest).ConfigureAwait(false),

            ProbeType.IcmpPing => await new IcmpProbe()
                .ExecuteAsync(target, _request.PingSamples, probeRequest).ConfigureAwait(false),

            ProbeType.TraceRoute => await new IcmpProbe()
                .TraceRouteAsync(target, maxHops: 15, samplesPerHop: 2, probeRequest).ConfigureAwait(false),

            ProbeType.Ntp => await new NtpProbe()
                .ExecuteAsync(target, probeRequest).ConfigureAwait(false),

            ProbeType.Dns => await ExecuteDnsAsync(target, step, probeRequest).ConfigureAwait(false),

            ProbeType.Http => await ExecuteHttpAsync(target, step, probeRequest).ConfigureAwait(false),

            ProbeType.Tls => await new TlsProbe()
                .ExecuteAsync(target, ParsePort(step) ?? 443, SniHost(), probeRequest)
                .ConfigureAwait(false),

            ProbeType.Smtp => await new SmtpProbe { StartTlsEnabled = true }
                .ExecuteAsync(target, ParsePort(step) ?? 25, probeRequest).ConfigureAwait(false),

            ProbeType.Ldap => await new LdapProbe()
                .ExecuteAsync(
                    _request.RequestedTarget,
                    ParsePort(step) ?? (step.Parameters.TryGetValue("ssl", out var s) && s == "true" ? 636 : 389),
                    step.Parameters.TryGetValue("ssl", out var ssl) && ssl == "true",
                    ResolveBindMode(step),
                    ResolveBindMode(step) == LdapBindMode.Explicit ? _request.ExplicitCredential : null,
                    probeRequest).ConfigureAwait(false),

            ProbeType.SqlServer => await new SqlServerProbe()
                .ExecuteAsync(
                    target,
                    _request.SqlInstanceName,
                    // 未指定实例名时按默认实例直测 TCP 1433，不依赖 SQL Browser（UDP 1434 常被关闭/拦截）
                    _request.SqlFixedPort ?? (string.IsNullOrWhiteSpace(_request.SqlInstanceName) ? 1433 : null),
                    _request.SqlCredential,
                    _request.TrySqlLogin,
                    probeRequest).ConfigureAwait(false),

            ProbeType.Smb => await new SmbProbe()
                .ExecuteAsync(target, ParsePort(step) ?? 445, probeRequest).ConfigureAwait(false),

            ProbeType.Rdp => await new RdpProbe()
                .ExecuteAsync(target, ParsePort(step) ?? 3389, probeRequest).ConfigureAwait(false),

            ProbeType.WinRm => await new WinRmProbe()
                .ExecuteAsync(target, ParsePort(step) ?? 5985,
                    useHttps: step.Parameters.TryGetValue("https", out var h) && h == "true",
                    probeRequest).ConfigureAwait(false),

            ProbeType.Ssh => await new SshProbe()
                .ExecuteAsync(target, ParsePort(step) ?? 22, probeRequest).ConfigureAwait(false),

            _ => UnsupportedStep(step, probeRequest),
        };
    }

    private static ProbeRun UnsupportedStep(ScenarioStep step, ProbeRequest request)
    {
        var run = new ProbeRun
        {
            RunId = request.RunId,
            Parameters = request.Parameters,
            State = ProbeState.Completed,
            Transport = TransportOutcome.NotExecuted,
            Protocol = ProtocolOutcome.NotSupported,
            ProtocolDetail = $"探针类型 {step.ProbeType} 在本版本未实现，状态=未支持。不用其他探针结果冒充。",
        };
        run.AddObservation(Observation.Now(run.ProtocolDetail, step.Name));
        return run;
    }

    private async Task<ProbeRun> ExecuteDnsAsync(
        IPAddress targetServer, ScenarioStep step, ProbeRequest request)
    {
        var probe = new DnsProbe();
        var query = Expand(step.Parameters.GetValueOrDefault("query", "{target}"))
            .Replace("{target}", _request.RequestedTarget);
        var typeText = step.Parameters.GetValueOrDefault("recordType", "A");
        var type = Enum.TryParse<DnsRecordType>(typeText, ignoreCase: true, out var t)
            ? t : DnsRecordType.A;

        // 目标为 IP 字面量时，A/AAAA 查询不适用——如实标记为跳过，不制造 NXDOMAIN 噪音
        if (IPAddress.TryParse(query, out _) && type is DnsRecordType.A or DnsRecordType.AAAA)
        {
            var skipped = new ProbeRun
            {
                RunId = request.RunId,
                Parameters = request.Parameters,
                State = ProbeState.Completed,
                Transport = TransportOutcome.NotExecuted,
                Protocol = ProtocolOutcome.NotExecuted,
            };
            skipped.AddObservation(Observation.Now(
                $"目标 {query} 为 IP 地址，{type} 记录查询不适用，已跳过。", step.Name));
            return skipped;
        }

        // DNS 服务器选择：
        // - dnsServer=target：场景意图是验证目标自身的 DNS 服务（AD 模板）
        // - 默认用本机系统 DNS：真实语义是"客户端按当前配置解析"
        IPAddress dnsServer;
        if (step.Parameters.GetValueOrDefault("dnsServer") == "target" ||
            step.Parameters.ContainsKey("useTargetAsDns"))
        {
            dnsServer = targetServer;
        }
        else
        {
            dnsServer = request.DnsServer ?? SystemDnsServer() ?? targetServer;
        }

        return await probe.ExecuteAsync(dnsServer, query, type, request).ConfigureAwait(false);
    }

    private async Task<ProbeRun> ExecuteHttpAsync(
        IPAddress target, ScenarioStep step, ProbeRequest request)
    {
        var urlText = step.Parameters.GetValueOrDefault("url");
        Uri uri;
        if (string.IsNullOrEmpty(urlText))
        {
            uri = new Uri($"http://{_request.RequestedTarget}/");
        }
        else
        {
            var expanded = Expand(urlText).Replace("{target}", _request.RequestedTarget);
            uri = Uri.TryCreate(expanded, UriKind.Absolute, out var u) ? u
                : new Uri($"https://{expanded}");
        }

        return await new HttpProbe(_resolver).ExecuteAsync(uri, request, new HttpProbeOptions
        {
            UseGet = step.Parameters.GetValueOrDefault("method", "GET") != "HEAD",
            DangerAcceptInvalidTls = _request.HttpAllowInvalidTls,
        }).ConfigureAwait(false);
    }

    private static IPAddress? SystemDnsServer()
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                var dns = nic.GetIPProperties().DnsAddresses
                    .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (dns is not null) return dns;
            }
        }
        catch
        {
            // 网卡枚举失败回退到目标
        }
        return null;
    }

    private LdapBindMode ResolveBindMode(ScenarioStep step)
    {
        // 步骤参数优先（如 AD 模板的匿名目录可达性检查），其次请求级默认
        var text = step.Parameters.GetValueOrDefault("bindMode");
        return text?.ToLowerInvariant() switch
        {
            "anonymous" => LdapBindMode.Anonymous,
            "explicit" => LdapBindMode.Explicit,
            "current" or "currentidentity" => LdapBindMode.CurrentIdentity,
            _ => _request.LdapBindMode,
        };
    }

    private string SniHost() =>
        IPAddress.TryParse(_request.RequestedTarget, out _) ? _request.RequestedTarget : _request.RequestedTarget;

    private int? ParsePort(ScenarioStep step) =>
        step.Parameters.TryGetValue("port", out var p) && int.TryParse(p, out var port) ? port : null;

    private IReadOnlyDictionary<string, string> ExpandParameters(
        ScenarioStep step) =>
        step.Parameters.ToDictionary(
                kv => kv.Key,
                kv => Expand(kv.Value))
            .Concat(
            [
                // 步骤名随结果留存，供 UI 与报告展示
                new KeyValuePair<string, string>("__stepName", step.Name),
            ])
            .ToDictionary(kv => kv.Key, kv => kv.Value);

    private string Expand(string text) => text
        .Replace("{domain}", _request.DomainName ?? "")
        .Replace("{target}", _request.RequestedTarget);
}
