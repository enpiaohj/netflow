using NetFlow.Domain;
using NetFlow.Reporting;

namespace NetFlow.Application;

/// <summary>证据工厂：探针运行 → 结构化证据记录。</summary>
public static class EvidenceFactory
{
    public static Evidence FromProbe(RunId runId, ProbeRun probe)
    {
        var text = string.Join("\n",
            probe.Observations.Select(o => $"{o.ObservedUtc:HH:mm:ss.fff} [{o.Source}] {o.Text}"));
        return new Evidence
        {
            RunId = runId,
            ProbeId = probe.Id,
            Kind = EvidenceKind.ProbeRawOutput,
            Side = SourceSide.Local,
            CapturedUtc = DateTimeOffset.UtcNow,
            Summary = RedactionService.Apply(text),
            ContentHash = RedactionService.Sha256(text),
            Redaction = RedactionLevel.Redacted,
        };
    }
}

/// <summary>
/// 发现工厂：基于探针结果生成结论。每条建议必须对应至少一个事实
/// （设计文档 5.3）。规则版本绑定报告。
/// </summary>
public static class FindingFactory
{
    public static IReadOnlyList<Finding> CreateFindings(
        DiagnosisRun run, ScenarioTemplate? template,
        bool canceled = false, string? fatal = null)
    {
        var findings = new List<Finding>();

        if (fatal is not null)
        {
            findings.Add(new Finding
            {
                RunId = run.Id,
                Severity = Severity.Error,
                Level = ConclusionLevel.Fail,
                ObservedFacts = [$"任务在执行中失败：{fatal}"],
                Limitations = ["已完成的检查项仍有效；失败点之后的检查未执行"],
                NextSteps = ["修正任务参数或环境后重试"],
                RuleVersion = ConclusionEvaluator.RuleVersion,
            });
            return findings;
        }

        if (canceled)
        {
            findings.Add(new Finding
            {
                RunId = run.Id,
                Severity = Severity.Info,
                Level = ConclusionLevel.Canceled,
                ObservedFacts = [$"任务被用户取消；已执行 {run.Probes.Count} 项检查"],
                Limitations = ["取消后的检查未执行"],
                RuleVersion = ConclusionEvaluator.RuleVersion,
            });
        }

        foreach (var p in run.Probes)
        {
            var verdict = ConclusionEvaluator.Evaluate(p.Transport, p.Protocol);
            if (verdict.Level is ConclusionLevel.Pass or ConclusionLevel.Skipped)
                continue;

            var facts = p.Observations
                .Select(o => o.Text)
                .Take(6)
                .ToList();
            if (facts.Count == 0)
                facts.Add($"检查项 {p.Parameters.ProbeType}：传输层 {p.Transport}，协议层 {p.Protocol}");

            findings.Add(new Finding
            {
                RunId = run.Id,
                Severity = verdict.Level switch
                {
                    ConclusionLevel.Fail => Severity.Error,
                    ConclusionLevel.Warning => Severity.Warning,
                    _ => Severity.Info,
                },
                Level = verdict.Level,
                ObservedFacts = facts,
                Inference = verdict.Level is ConclusionLevel.Unconfirmed or ConclusionLevel.NotChecked
                    ? null  // 未确认场景不给推断
                    : verdict.Rationale,
                Limitations = [.. verdict.Limitations],
                NextSteps = NextStepsFor(p, verdict.Level),
                RuleVersion = ConclusionEvaluator.RuleVersion,
            });
        }

        // 总体结论
        int pass = run.Probes.Count(p =>
            ConclusionEvaluator.Evaluate(p.Transport, p.Protocol).Level == ConclusionLevel.Pass);
        int warn = run.Probes.Count(p =>
            ConclusionEvaluator.Evaluate(p.Transport, p.Protocol).Level == ConclusionLevel.Warning);
        int fail = run.Probes.Count(p =>
            ConclusionEvaluator.Evaluate(p.Transport, p.Protocol).Level == ConclusionLevel.Fail);
        int unconfirmed = run.Probes.Count(p =>
            ConclusionEvaluator.Evaluate(p.Transport, p.Protocol).Level == ConclusionLevel.Unconfirmed);
        int notChecked = run.Probes.Count(p =>
            ConclusionEvaluator.Evaluate(p.Transport, p.Protocol).Level == ConclusionLevel.NotChecked);

        findings.Add(new Finding
        {
            RunId = run.Id,
            Severity = fail > 0 ? Severity.Error : warn > 0 ? Severity.Warning : Severity.Info,
            Level = fail > 0 ? ConclusionLevel.Fail
                : unconfirmed > 0 ? ConclusionLevel.Unconfirmed
                : warn > 0 ? ConclusionLevel.Warning
                : ConclusionLevel.Pass,
            ObservedFacts =
            [
                $"共执行 {run.Probes.Count} 项检查：通过 {pass}，警告 {warn}，" +
                $"失败 {fail}，未确认 {unconfirmed}，未检查 {notChecked}。",
            ],
            Inference = fail == 0 && unconfirmed == 0
                ? "在本次观察范围内，所选检查项均未发现明确的网络或服务故障事实。"
                : null,
            Limitations =
            [
                "仅本机视角；目标端视角需要该端的抓包或日志",
                "结论受本次采样时间窗口与网络环境影响",
            ],
            NextSteps = fail > 0 || unconfirmed > 0
                ?
                [
                    "针对失败/未确认项，在目标端按报告时间窗口同步观察",
                    "必要时启用定向抓包并重新运行该检查项",
                ]
                : ["如需持续观察，可创建监测任务"],
            RuleVersion = ConclusionEvaluator.RuleVersion,
        });

        return findings;
    }

    /// <summary>按探针类型给出下一步建议（可复制、可执行）。</summary>
    private static IReadOnlyList<string> NextStepsFor(ProbeRun p, ConclusionLevel level)
    {
        switch (p.Parameters.ProbeType)
        {
            case ProbeType.TcpConnect when level == ConclusionLevel.Unconfirmed:
                return
                [
                    $"在目标端确认 {p.Parameters.Port} 端口是否有服务监听",
                    "在本机与目标端按同一时间窗口同步抓包，核对 SYN 是否到达",
                ];
            case ProbeType.TcpConnect when level == ConclusionLevel.Fail:
                return
                [
                    $"确认目标 {p.Parameters.Port} 端口的服务状态与防火墙入站规则（配置证据）",
                ];
            case ProbeType.UdpDatagram or ProbeType.Ntp when level == ConclusionLevel.Unconfirmed:
                return
                [
                    "确认目标服务是否启用该协议",
                    "在服务端抓包核对请求是否到达、回应是否发出",
                    "使用自定义报文调整请求内容后重试",
                ];
            case ProbeType.Dns when p.Protocol == ProtocolOutcome.ServiceError:
                return
                [
                    "在 DNS 服务器上核对记录与区域配置",
                    "比较多台 DNS 服务器的应答差异（以基线为准，不默认某一方正确）",
                ];
            case ProbeType.Tls:
                return
                [
                    "核对证书主题/SAN 与访问主机名是否匹配",
                    "确认证书有效期与签发链",
                ];
            case ProbeType.Http when level == ConclusionLevel.Warning:
                return
                [
                    "查看服务端应用日志定位该状态码的来源",
                    "按业务预期调整可接受状态码规则",
                ];
            case ProbeType.Ldap when level == ConclusionLevel.Warning:
                return
                [
                    "核对绑定凭据与账户状态",
                    "确认允许的认证方式（协商/简单绑定）",
                ];
            case ProbeType.SqlServer:
                return
                [
                    "确认 SQL Browser 服务与实例端口配置",
                    "核对 SQL 登录账户与认证方式",
                ];
            default:
                return ["结合本次报告的时间窗口在目标端做对应观察"];
        }
    }
}
