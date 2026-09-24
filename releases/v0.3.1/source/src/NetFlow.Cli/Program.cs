using System.Net;
using System.Net.Sockets;
using NetFlow.Application;
using NetFlow.Capture;
using NetFlow.Domain;
using NetFlow.Persistence;
using NetFlow.Probes;
using NetFlow.Probes.DnsProtocol;
using NetFlow.Reporting;

namespace NetFlow.Cli;

/// <summary>
/// NetFlow 命令行接口（M3 能力的基础）。
/// 用法示例：
///   NetFlow.Cli tcp 192.168.10.11:445
///   NetFlow.Cli dns corp.example.com --server 192.168.10.11 --type SRV
///   NetFlow.Cli ntp 192.168.10.11
///   NetFlow.Cli smb 192.168.10.11
///   NetFlow.Cli ldap 192.168.10.11
///   NetFlow.Cli sql 192.168.10.15
///   NetFlow.Cli scenario builtin.ad-client-dc 192.168.10.11 --domain corp.example.com
///   NetFlow.Cli capture-status &lt;evidenceRoot&gt;
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        var rest = args[1..];
        var options = ParseOptions(rest);
        var positional = rest.Where(a => !a.StartsWith('-')).ToArray();

        var timeout = TimeSpan.FromSeconds(
            double.TryParse(options.GetValueOrDefault("timeout", "3"), out var t) ? t : 3);
        var runId = RunId.New();

        try
        {
            ProbeRun run;
            switch (command)
            {
                case "tcp":
                {
                    var (host, port) = ParseHostPort(positional[0], 80);
                    var ip = await ResolveAsync(host).ConfigureAwait(false);
                    run = await new TcpConnectProbe().ExecuteAsync(ip, port, NewRequest(runId, host, port, timeout)).ConfigureAwait(false);
                    break;
                }
                case "dns":
                {
                    var server = options.TryGetValue("server", out var s) ? IPAddress.Parse(s) : FirstSystemDns()
                        ?? throw new InvalidOperationException("未找到系统 DNS，请用 --server 指定");
                    var type = Enum.TryParse<DnsRecordType>(options.GetValueOrDefault("type", "A"), true, out var dt)
                        ? dt : DnsRecordType.A;
                    run = await new DnsProbe().ExecuteAsync(server, positional[0], type,
                        NewRequest(runId, positional[0], 53, timeout)).ConfigureAwait(false);
                    break;
                }
                case "ntp":
                {
                    var ip = await ResolveAsync(positional[0]).ConfigureAwait(false);
                    run = await new NtpProbe().ExecuteAsync(ip, NewRequest(runId, positional[0], 123, timeout)).ConfigureAwait(false);
                    break;
                }
                case "smb":
                {
                    var ip = await ResolveAsync(positional[0]).ConfigureAwait(false);
                    run = await new SmbProbe().ExecuteAsync(ip, 445, NewRequest(runId, positional[0], 445, timeout)).ConfigureAwait(false);
                    break;
                }
                case "ldap":
                {
                    run = await new LdapProbe().ExecuteAsync(positional[0], 389, false,
                        LdapBindMode.Anonymous, null, NewRequest(runId, positional[0], 389, timeout)).ConfigureAwait(false);
                    break;
                }
                case "sql":
                {
                    var ip = await ResolveAsync(positional[0]).ConfigureAwait(false);
                    run = await new SqlServerProbe().ExecuteAsync(ip, options.GetValueOrDefault("instance"),
                        null, null, options.ContainsKey("login"),
                        NewRequest(runId, positional[0], 1433, timeout)).ConfigureAwait(false);
                    break;
                }
                case "http":
                {
                    var uri = new Uri(positional[0]);
                    run = await new HttpProbe().ExecuteAsync(uri, NewRequest(runId, positional[0], uri.Port, timeout)).ConfigureAwait(false);
                    break;
                }
                case "tls":
                {
                    var (host, port) = ParseHostPort(positional[0], 443);
                    var ip = await ResolveAsync(host).ConfigureAwait(false);
                    run = await new TlsProbe().ExecuteAsync(ip, port, host, NewRequest(runId, host, port, timeout)).ConfigureAwait(false);
                    break;
                }
                case "scenario":
                {
                    if (positional.Length < 2)
                    {
                        Console.Error.WriteLine("用法：scenario <templateId> <target> [--domain x]");
                        return 2;
                    }
                    var evidenceRoot = options.GetValueOrDefault("evidence-root",
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetFlow", "evidence"));
                    await using var repository = new DiagnosisRepository(
                        Path.Combine(Path.GetDirectoryName(evidenceRoot)!, "netflow.db"));
                    await repository.InitializeAsync().ConfigureAwait(false);

                    var orchestrator = new DiagnosisOrchestrator();
                    orchestrator.StatusChanged += (_, msg) => Console.WriteLine($"[进度] {msg}");
                    var outcome = await orchestrator.ExecuteAsync(new DiagnosisRequest
                    {
                        RequestedTarget = positional[1],
                        ScenarioId = positional[0],
                        DomainName = options.GetValueOrDefault("domain"),
                        Timeout = timeout,
                    }, repository).ConfigureAwait(false);

                    var export = new ReportExportService();
                    var artifacts = export.ExportAll(outcome.Run, evidenceRoot);
                    outcome.Run.Artifacts.AddRange(artifacts);
                    await repository.SaveRunAsync(outcome.Run).ConfigureAwait(false);

                    Console.WriteLine();
                    Console.WriteLine($"任务 ID：{outcome.Run.Id}");
                    foreach (var a in artifacts)
                        Console.WriteLine($"报告：{a.AbsolutePath}");
                    return 0;
                }
                default:
                    PrintUsage();
                    return 2;
            }

            PrintRun(run);
            return run.Transport is TransportOutcome.Success && run.Protocol is ProtocolOutcome.Success
                ? 0 : 1;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"错误：{ex.Message}");
            return 2;
        }
    }

    private static ProbeRequest NewRequest(RunId runId, string target, int? port, TimeSpan timeout) => new()
    {
        RunId = runId,
        Parameters = new ProbeParameters
        {
            ProbeType = ProbeType.TcpConnect,
            RequestedTarget = target,
            Port = port,
            Timeout = timeout,
        },
    };

    private static void PrintRun(ProbeRun run)
    {
        var verdict = ConclusionEvaluator.Evaluate(run.Transport, run.Protocol);
        Console.WriteLine();
        Console.WriteLine($"探针：{run.Parameters.ProbeType}｜结论：{verdict.Level}");
        Console.WriteLine($"说明：{verdict.Rationale}");
        if (run.ProtocolDetail is not null) Console.WriteLine($"协议：{run.ProtocolDetail}");
        foreach (var obs in run.Observations)
            Console.WriteLine($"  {obs.ObservedUtc.LocalDateTime:HH:mm:ss.fff} {obs.Text}");
        Console.WriteLine($"规则版本：{ConclusionEvaluator.RuleVersion}");
    }

    private static Dictionary<string, string> ParseOptions(string[] args)
    {
        var map = new Dictionary<string, string>();
        for (int i = 0; i + 1 < args.Length; i++)
        {
            if (args[i].StartsWith("--"))
            {
                map[args[i][2..]] = args[i + 1];
                i++;
            }
        }
        return map;
    }

    private static (string Host, int Port) ParseHostPort(string text, int defaultPort)
    {
        var parts = text.Split(':');
        return parts.Length > 1
            ? (parts[0], int.TryParse(parts[1], out var p) ? p : defaultPort)
            : (text, defaultPort);
    }

    private static async Task<IPAddress> ResolveAsync(string host)
    {
        if (IPAddress.TryParse(host, out var ip)) return ip;
        var addrs = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
        return addrs.First() ?? throw new ProbeNameResolutionException(host,
            new Exception("无地址"));
    }

    private static IPAddress? FirstSystemDns()
    {
        foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                continue;
            var dns = nic.GetIPProperties().DnsAddresses
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            if (dns is not null) return dns;
        }
        return null;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            NetFlow v0.3.1 —— Windows 网络与服务诊断

            用法：
              NetFlow.Cli tcp <host:port>                 TCP 连接探针
              NetFlow.Cli dns <name> [--server ip] [--type A|SRV|MX|TXT]
              NetFlow.Cli ntp <ip>                        NTP 探针
              NetFlow.Cli smb <ip>                        SMB2 协商探针
              NetFlow.Cli ldap <host>                     LDAP 匿名绑定 + RootDSE
              NetFlow.Cli sql <ip> [--instance x] [--login]
              NetFlow.Cli http <url>                      HTTP 分阶段探针
              NetFlow.Cli tls <host[:port]>               TLS 证书检查
              NetFlow.Cli scenario <templateId> <target> [--domain x] [--evidence-root path]
                            （报告输出到 %LOCALAPPDATA%\NetFlow\evidence\<runId>\）

            内置模板：
            """);
        foreach (var t in BuiltinTemplates.All)
            Console.WriteLine($"  {t.Id,-28} {t.Name}（{t.Direction}）");
        Console.WriteLine();
        Console.WriteLine("状态红线：UDP 无响应=未确认；端口可连接≠服务可用；本机无响应≠防火墙丢包。");
    }
}
