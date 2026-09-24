using System.Net;
using NetFlow.Domain;
using NetFlow.Probes;
using Xunit;
using Xunit.Abstractions;

namespace NetFlow.IntegrationTests;

/// <summary>
/// 集成测试环境配置。凭据只存在于 testsettings.local.json（已 gitignore）。
/// </summary>
public sealed class TestEnv
{
    public IPAddress DcIp { get; init; } = IPAddress.Parse("192.168.10.11");
    public string DcFqdn { get; init; } = "dc01.corp.example.com";
    public string DomainFqdn { get; init; } = "corp.example.com";
    public string NetbiosDomain { get; init; } = "EXAMPLE";
    public IPAddress FsIp { get; init; } = IPAddress.Parse("192.168.10.15");
    public IPAddress EsxiIp { get; init; } = IPAddress.Parse("192.168.10.200");
    public string AdminUser { get; init; } = "EXAMPLE\\testadmin";
    public string AdminPassword { get; init; } = "";
    public string NormalUser { get; init; } = "EXAMPLE\\testuser01";
    public string NormalPassword { get; init; } = "";

    public static TestEnv? TryLoad()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(baseDir, "testsettings.local.json"),
            Path.Combine(Directory.GetCurrentDirectory(), "testsettings.local.json"),
            Path.Combine(Directory.GetCurrentDirectory(),
                "..", "..", "..", "testsettings.local.json"),
        };
        foreach (var path in candidates)
        {
            if (!File.Exists(path)) continue;
            var json = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path)).RootElement;

            string Get(string section, string key, string fallback) =>
                json.TryGetProperty(section, out var s) &&
                s.TryGetProperty(key, out var v) ? v.GetString() ?? fallback : fallback;

            return new TestEnv
            {
                DcIp = IPAddress.Parse(Get("Dc", "Host", "192.168.10.11")),
                DcFqdn = Get("Dc", "Fqdn", "dc01.corp.example.com"),
                DomainFqdn = Get("Dc", "DomainFqdn", "corp.example.com"),
                NetbiosDomain = Get("Dc", "NetbiosDomain", "EXAMPLE"),
                FsIp = IPAddress.Parse(Get("FileServer", "Host", "192.168.10.15")),
                EsxiIp = IPAddress.Parse(Get("Esxi", "Host", "192.168.10.200")),
                AdminUser = Get("DomainAdmin", "User", "EXAMPLE\\testadmin"),
                AdminPassword = Get("DomainAdmin", "Password", ""),
                NormalUser = Get("DomainUser", "User", "EXAMPLE\\testuser01"),
                NormalPassword = Get("DomainUser", "Password", ""),
            };
        }
        return null;
    }
}

/// <summary>状态判定断言帮助。</summary>
public static class VerdictAssert
{
    public static ConclusionLevel LevelOf(ProbeRun run) =>
        ConclusionEvaluator.Evaluate(run.Transport, run.Protocol).Level;

    public static void AssertNotClosedClaim(ProbeRun run)
    {
        var verdict = ConclusionEvaluator.Evaluate(run.Transport, run.Protocol);
        Assert.DoesNotContain("关闭", verdict.Rationale);
        Assert.DoesNotContain("被防火墙", verdict.Rationale);
        foreach (var obs in run.Observations)
        {
            Assert.False(
                obs.Text.Contains("端口关闭", StringComparison.Ordinal),
                "观察记录中不得出现“端口关闭”的归因表述");
        }
    }
}
