using System.Net;
using NetFlow.Application;
using NetFlow.Domain;
using NetFlow.Probes;
using Xunit;
using Xunit.Abstractions;

namespace NetFlow.IntegrationTests;

/// <summary>
/// 文件服务器 / SQL / IIS 与 ESXi 证书不匹配用例（设计文档第 12 节验收）。
/// </summary>
public class FileServerAndTlsTests
{
    private readonly ITestOutputHelper _output;
    private readonly TestEnv _env;

    public FileServerAndTlsTests(ITestOutputHelper output)
    {
        _output = output;
        _env = TestEnv.TryLoad() ?? new TestEnv();
    }

    private static ProbeRequest NewRequest(RunId runId, string target, int port, int timeoutSec = 5) => new()
    {
        RunId = runId,
        Parameters = new ProbeParameters
        {
            ProbeType = ProbeType.TcpConnect,
            RequestedTarget = target,
            Port = port,
            Timeout = TimeSpan.FromSeconds(timeoutSec),
        },
    };

    [Fact]
    public async Task FileServer_Smb_Sql_Rdp_WinRm_AreOpen()
    {
        foreach (var port in new[] { 445, 1433, 3389, 5985 })
        {
            var run = await new TcpConnectProbe().ExecuteAsync(
                _env.FsIp, port, NewRequest(RunId.New(), "fs01", port));
            _output.WriteLine($"TCP {port}: {run.Transport}");
            Assert.Equal(TransportOutcome.Success, run.Transport);
        }
    }

    [Fact]
    public async Task FileServer_IisHttp_ReturnsValidResponse()
    {
        var run = await new HttpProbe().ExecuteAsync(
            new Uri($"http://{_env.FsIp}/"),
            NewRequest(RunId.New(), _env.FsIp.ToString(), 80));

        _output.WriteLine(string.Join("\n", run.Observations.Select(o => o.Text)));
        Assert.Equal(TransportOutcome.Success, run.Transport);
    }

    [Fact]
    public async Task SqlBrowser_DiscoveryOrTimeout_IsHonest()
    {
        var run = await new SqlServerProbe().ExecuteAsync(
            _env.FsIp, null, null, null, tryLogin: false,
            NewRequest(RunId.New(), _env.FsIp.ToString(), 1433));

        _output.WriteLine(string.Join("\n", run.Observations.Select(o => o.Text)));
        // Browser 可能关闭（固定端口部署）→ 未确认；或发现成功 → 走到 TCP/登录阶段
        Assert.True(
            run.Protocol is ProtocolOutcome.NoResponse or ProtocolOutcome.Success
                or ProtocolOutcome.NotExecuted,
            $"实际：{run.Transport}/{run.Protocol} {run.ProtocolDetail}");
    }

    [Fact]
    public async Task Esxi_TlsNameMismatch_IsReportedNotIgnored()
    {
        // 验收用例：TLS 证书名称错误 —— ESXi 用 IP 访问，证书不含该名称
        var run = await new TlsProbe().ExecuteAsync(
            _env.EsxiIp, 443, _env.EsxiIp.ToString(),
            NewRequest(RunId.New(), _env.EsxiIp.ToString(), 443));

        _output.WriteLine($"结论级别：{VerdictAssert.LevelOf(run)}");
        _output.WriteLine(string.Join("\n", run.Observations.Select(o => o.Text)));

        // 证书验证必须如实失败，不得悄悄通过
        Assert.Equal(ProtocolOutcome.ProtocolError, run.Protocol);
        Assert.Contains(run.Observations,
            o => o.Text.Contains("证书验证") || o.Text.Contains("证书链"));
        Assert.Equal(TransportOutcome.Success, run.Transport); // TCP 是通的
    }

    [Fact]
    public async Task Esxi_HttpWithInvalidTls_OnlySucceedsWhenExplicitlyAllowed()
    {
        // 默认（不忽略证书错误）：HTTPS 探针应报告 TLS 失败
        var strict = await new HttpProbe().ExecuteAsync(
            new Uri($"https://{_env.EsxiIp}/"),
            NewRequest(RunId.New(), _env.EsxiIp.ToString(), 443, timeoutSec: 15),
            new HttpProbeOptions { UseSystemProxy = false });
        _output.WriteLine($"严格模式：{strict.Protocol}｜{strict.ProtocolDetail}");
        Assert.NotEqual(ProtocolOutcome.Success, strict.Protocol);

        // 显式开启（记录在案）：请求可以完成
        var lenient = await new HttpProbe().ExecuteAsync(
            new Uri($"https://{_env.EsxiIp}/"),
            NewRequest(RunId.New(), _env.EsxiIp.ToString(), 443, timeoutSec: 15),
            new HttpProbeOptions { DangerAcceptInvalidTls = true, UseSystemProxy = false });
        _output.WriteLine($"显式忽略模式：{lenient.Protocol}｜{lenient.ProtocolDetail}");
        _output.WriteLine("  " + string.Join(" | ", lenient.Observations.Select(o => o.Text)));
        Assert.Equal(ProtocolOutcome.Success, lenient.Protocol);
    }

    [Fact]
    public async Task ClosedPort_IisHttps_Refused()
    {
        var run = await new TcpConnectProbe().ExecuteAsync(
            _env.FsIp, 443, NewRequest(RunId.New(), "fs01", 443, timeoutSec: 2));
        _output.WriteLine($"TCP 443: {run.Transport}（{run.ErrorCode}）");
        Assert.True(
            run.Transport is TransportOutcome.Refused or TransportOutcome.Timeout,
            $"实际：{run.Transport}");
        Assert.NotEqual(TransportOutcome.Success, run.Transport);
    }
}
