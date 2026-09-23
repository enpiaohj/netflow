using System.Net;
using NetFlow.Domain;
using NetFlow.Probes;
using NetFlow.Probes.DnsProtocol;
using Xunit;
using Xunit.Abstractions;

namespace NetFlow.IntegrationTests;

/// <summary>
/// AD 场景真实环境测试：对测试域控执行设计文档 12 节的核心验收用例。
/// 本机为工作组机器，Kerberos SSO 相关用例按「显式凭据」级别验证。
/// </summary>
public class AdScenarioTests
{
    private readonly ITestOutputHelper _output;
    private readonly TestEnv _env;

    public AdScenarioTests(ITestOutputHelper output)
    {
        _output = output;
        _env = TestEnv.TryLoad() ?? new TestEnv();
    }

    private static ProbeRequest NewRequest(RunId runId, string target, int port) => new()
    {
        RunId = runId,
        Parameters = new ProbeParameters
        {
            ProbeType = ProbeType.TcpConnect,
            RequestedTarget = target,
            Port = port,
            Timeout = TimeSpan.FromSeconds(3),
        },
    };

    [Fact]
    public async Task Dc_CoreAdPorts_AreOpen()
    {
        foreach (var port in new[] { 53, 88, 135, 389, 445, 636, 3268 })
        {
            var run = await new TcpConnectProbe().ExecuteAsync(
                _env.DcIp, port, NewRequest(RunId.New(), _env.DcFqdn, port));
            _output.WriteLine($"TCP {port}: {run.Transport}");
            Assert.Equal(TransportOutcome.Success, run.Transport);
            Assert.Equal(ConclusionLevel.Pass, VerdictAssert.LevelOf(run));
        }
    }

    [Fact]
    public async Task Dc_DnsSrvQuery_ReturnsDcTargets()
    {
        var probe = new DnsProbe();
        var run = await probe.ExecuteAsync(
            _env.DcIp,
            $"_ldap._tcp.dc._msdcs.{_env.DomainFqdn}",
            DnsRecordType.SRV,
            NewRequest(RunId.New(), _env.DcFqdn, 53));

        _output.WriteLine($"RCODE/结论：{run.Protocol}｜{run.ProtocolDetail}");
        foreach (var obs in run.Observations)
            _output.WriteLine($"  {obs.Text}");

        Assert.Equal(TransportOutcome.Success, run.Transport);
        Assert.Equal(ProtocolOutcome.Success, run.Protocol);
        Assert.Contains(run.Observations, o => o.Text.Contains("SRV"));
    }

    [Fact]
    public async Task Dc_NtpQuery_ReturnsServerResponse()
    {
        var run = await new NtpProbe().ExecuteAsync(
            _env.DcIp, NewRequest(RunId.New(), _env.DcFqdn, 123));

        _output.WriteLine(string.Join("\n", run.Observations.Select(o => o.Text)));
        Assert.Equal(ProtocolOutcome.Success, run.Protocol);
    }

    [Fact]
    public async Task Dc_SmbNegotiate_Succeeds()
    {
        var run = await new SmbProbe().ExecuteAsync(
            _env.DcIp, 445, NewRequest(RunId.New(), _env.DcFqdn, 445));

        _output.WriteLine(string.Join("\n", run.Observations.Select(o => o.Text)));
        Assert.Equal(ProtocolOutcome.Success, run.Protocol);
        Assert.Contains(run.Observations, o => o.Text.Contains("协商成功"));
    }

    [Fact]
    public async Task Dc_LdapAnonymousBind_RootDseWorks()
    {
        // 本开发机 DNS 指向公网（8.8.8.8），无法解析内网 FQDN——
        // 这正是 NetFlow 要暴露的典型问题。此处按 IP 直连验证 LDAP 服务本身。
        var run = await new LdapProbe().ExecuteAsync(
            _env.DcIp.ToString(), 389, false, LdapBindMode.Anonymous, null,
            NewRequest(RunId.New(), _env.DcIp.ToString(), 389));

        _output.WriteLine(string.Join("\n", run.Observations.Select(o => o.Text)));
        Assert.Equal(ProtocolOutcome.Success, run.Protocol);
        Assert.Contains(run.Observations, o =>
            o.Text.Contains("defaultNamingContext", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Dc_LdapExplicitBind_WithDomainAdmin_Succeeds()
    {
        if (_env.AdminPassword.Length == 0)
        {
            _output.WriteLine("未配置凭据，跳过显式绑定测试");
            return;
        }

        var parts = _env.AdminUser.Split('\\');
        var credential = new System.Net.NetworkCredential(
            parts[^1], _env.AdminPassword, parts.Length > 1 ? parts[0] : "");

        var run = await new LdapProbe().ExecuteAsync(
            _env.DcIp.ToString(), 389, false, LdapBindMode.Explicit, credential,
            NewRequest(RunId.New(), _env.DcIp.ToString(), 389));

        _output.WriteLine(string.Join("\n", run.Observations.Select(o => o.Text)));
        Assert.Equal(ProtocolOutcome.Success, run.Protocol);
    }

    [Fact]
    public async Task PublicDns_CannotResolveInternalNames_UnlikeDomainDns()
    {
        // 环境观测用例：公网 DNS 对内网名的解析与域内 DNS 的结果差异
        var probe = new DnsProbe();
        var viaPublic = await probe.ExecuteAsync(
            IPAddress.Parse("8.8.8.8"), _env.DcFqdn, DnsRecordType.A,
            NewRequest(RunId.New(), _env.DcFqdn, 53));
        _output.WriteLine("8.8.8.8 => " + string.Join(" | ", viaPublic.Observations.Select(o => o.Text)));

        var viaDomain = await probe.ExecuteAsync(
            _env.DcIp, _env.DcFqdn, DnsRecordType.A,
            NewRequest(RunId.New(), _env.DcFqdn, 53));
        _output.WriteLine("DomainDns => " + string.Join(" | ", viaDomain.Observations.Select(o => o.Text)));

        Assert.Equal(ProtocolOutcome.Success, viaDomain.Protocol);
        var publicAddrs = ExtractARecords(viaPublic);
        var domainAddrs = ExtractARecords(viaDomain);
        Assert.True(
            publicAddrs.Length == 0 ||
            !publicAddrs.OrderBy(x => x).SequenceEqual(domainAddrs.OrderBy(x => x)),
            "公网 DNS 不应返回与域内 DNS 一致的 A 记录");
    }

    [Fact]
    public async Task UdpClosedPort_ReportsUnconfirmed_NeverClosed()
    {
        // 验收用例：UDP 端口无响应（DC 上大概率无监听的高位 UDP 端口）
        var run = await new UdpProbe().ExecuteAsync(
            _env.DcIp, 5555,
            new UdpPayload { Text = "probe" },
            new ProbeRequest
            {
                RunId = RunId.New(),
                Parameters = new ProbeParameters
                {
                    ProbeType = ProbeType.UdpDatagram,
                    RequestedTarget = $"{_env.DcIp}:5555",
                    Port = 5555,
                    Timeout = TimeSpan.FromSeconds(2),
                },
            });

        _output.WriteLine(string.Join("\n", run.Observations.Select(o => o.Text)));
        VerdictAssert.AssertNotClosedClaim(run);
        // Windows 返回 ICMP 不可达 → 明确拒绝；或超时 → 未确认。两者都不得表述为"端口关闭"
        Assert.True(
            run.Protocol is ProtocolOutcome.NoResponse
            || run.Transport is TransportOutcome.Refused,
            $"实际观察：{run.Transport}/{run.Protocol}");
    }

    [Fact]
    public async Task Dc_TcpClosedHighPort_ReportsRefused()
    {
        // 验收用例：明确拒绝（RST）应区别于超时
        var run = await new TcpConnectProbe().ExecuteAsync(
            _env.DcIp, 47471, NewRequest(RunId.New(), _env.DcFqdn, 47471));
        _output.WriteLine($"TCP 47471: {run.Transport}（{run.ErrorCode}）");
        Assert.Equal(TransportOutcome.Refused, run.Transport);
        Assert.Equal(ConclusionLevel.Fail, VerdictAssert.LevelOf(run));
    }

    private static string[] ExtractARecords(ProbeRun run) =>
        run.Observations
            .Where(o => o.Text.StartsWith("A 记录："))
            .Select(o => o.Text.Split("→")[1].Split("（")[0].Trim())
            .ToArray();
}
