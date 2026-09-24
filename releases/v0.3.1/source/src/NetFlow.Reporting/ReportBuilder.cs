using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetFlow.Domain;

namespace NetFlow.Reporting;

/// <summary>
/// 报告生成（设计文档第 9 节报告契约）：
/// - HTML 完全离线、内容全部转义
/// - JSON 固定 schema 版本
/// - CSV 仅表格摘要
/// 每份报告包含：任务 ID、源/目标/解析、本地与 UTC 时间、应用/模板/规则版本、
/// 执行项目与参数、逐项事实/结论/限制/建议、证据索引与哈希、权限与未检查项、附件清单。
/// </summary>
public static class ReportBuilder
{
    public const string ReportSchemaVersion = "netflow-report/1.0";

    // ---- JSON ----

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string BuildJson(DiagnosisRun run)
    {
        var doc = new
        {
            schema = ReportSchemaVersion,
            title = $"{NetFlowInfo.ProductName} 诊断报告 {run.Id}",
            runId = run.Id.ToString(),
            generatedLocal = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz"),
            generatedUtc = DateTimeOffset.UtcNow,
            appVersion = run.AppVersion,
            ruleVersion = ConclusionEvaluator.RuleVersion,
            source = new
            {
                host = run.SourceHost,
                requestedAddress = run.RequestedSourceAddress,
                adapter = run.Adapter,
                elevated = run.Elevated,
            },
            target = new
            {
                requested = run.RequestedTarget,
                resolved = run.ResolvedAddresses,
            },
            scenario = run.Scenario is null ? null : new
            {
                run.Scenario.TemplateId,
                run.Scenario.TemplateName,
                run.Scenario.TemplateVersion,
                run.Scenario.Direction,
            },
            time = new { startUtc = run.StartUtc, endUtc = run.EndUtc },
            terminationReason = run.TerminationReason,
            probes = run.Probes.Select(p => new
            {
                p.Id,
                type = p.Parameters.ProbeType.ToString(),
                parameters = p.Parameters,
                state = p.State.ToString(),
                transport = p.Transport.ToString(),
                transportDetail = p.TransportDetail,
                protocol = p.Protocol.ToString(),
                protocolDetail = p.ProtocolDetail,
                resolved = p.ResolvedAddresses,
                sourceAddress = p.SourceAddress,
                startUtc = p.StartUtc,
                endUtc = p.EndUtc,
                stages = p.Stages,
                observations = p.Observations,
                errorCode = p.ErrorCode,
            }),
            findings = run.Findings.Select(f => new
            {
                f.Id,
                severity = f.Severity.ToString(),
                level = f.Level.ToString(),
                facts = f.ObservedFacts,
                inference = f.Inference,
                limitations = f.Limitations,
                nextSteps = f.NextSteps,
                evidenceIds = f.SupportingEvidenceIds.Select(e => e.ToString()),
                f.RuleVersion,
            }),
            evidences = run.Evidences.Select(e => new
            {
                e.Id,
                kind = e.Kind.ToString(),
                side = e.Side.ToString(),
                e.CapturedUtc,
                e.ArtifactPath,
                e.ContentHash,
                redaction = e.Redaction.ToString(),
            }),
            artifacts = run.Artifacts.Select(a => new
            {
                a.Format,
                a.AbsolutePath,
                a.Size,
                a.Sha256,
                retention = a.Retention.ToString(),
            }),
        };
        return JsonSerializer.Serialize(doc, JsonOpts);
    }

    // ---- CSV 摘要 ----

    public static string BuildCsv(DiagnosisRun run)
    {
        var sb = new StringBuilder();
        sb.AppendLine("探针,状态,传输,协议,结论,耗时(ms),目标,错误码");
        foreach (var p in run.Probes)
        {
            var verdict = ConclusionEvaluator.Evaluate(p.Transport, p.Protocol);
            sb.AppendLine(string.Join(',',
                Csv(p.Parameters.ProbeType.ToString()),
                Csv(p.State.ToString()),
                Csv(p.Transport.ToString()),
                Csv(p.Protocol.ToString()),
                Csv(verdict.Level.ToString()),
                p.Elapsed is { } e ? ((int)e.TotalMilliseconds).ToString() : "",
                Csv(p.Parameters.RequestedTarget),
                Csv(p.ErrorCode ?? "")));
        }
        return sb.ToString();
    }

    private static string Csv(string s) => $"\"{s.Replace("\"", "\"\"")}\"";

    // ---- HTML ----

    public static string BuildHtml(DiagnosisRun run, RedactionOptions? redaction = null)
    {
        var opt = redaction ?? new RedactionOptions();
        var sb = new StringBuilder(64 * 1024);
        sb.Append("""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">""");
        sb.Append("""<title>""").Append(E(NetFlowInfo.ProductName)).Append(" 诊断报告 ")
          .Append(E(run.Id.ToString())).Append("""</title>""");
        sb.Append("<style>").Append(OfflineCss).Append("</style></head><body>");
        sb.Append("<h1>").Append(E(NetFlowInfo.ProductName)).Append(" 诊断报告</h1>");
        sb.Append("<p class='muted'>任务 ID：").Append(E(run.Id.ToString()))
          .Append("｜生成时间：").Append(E(DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss zzz")))
          .Append("（UTC ").Append(E(DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm:ss")))
          .Append("）</p>");

        // 源与目标
        sb.Append("<h2>源与目标</h2><table>");
        sb.Append(Row("源主机", run.SourceHost));
        sb.Append(Row("目标", run.RequestedTarget));
        sb.Append(Row("解析地址", string.Join("、", run.ResolvedAddresses)));
        sb.Append(Row("源网卡", run.Adapter ?? "—"));
        sb.Append(Row("请求源地址", run.RequestedSourceAddress ?? "自动"));
        sb.Append(Row("管理员权限", run.Elevated ? "已提升" : "未提升"));
        sb.Append(Row("应用版本", run.AppVersion));
        sb.Append(Row("规则版本", ConclusionEvaluator.RuleVersion));
        sb.Append(Row("脱敏规则", RedactionOptions.RuleVersion + (opt.Enabled ? "（已启用）" : "（未启用——原始内容）")));
        if (run.Scenario is { } sc)
        {
            sb.Append(Row("场景模板", $"{sc.TemplateName}（{sc.TemplateId} v{sc.TemplateVersion}，{sc.Direction}）"));
        }
        if (run.TerminationReason is not null)
            sb.Append(Row("终止原因", run.TerminationReason));
        sb.Append("</table>");

        // 检查项
        sb.Append("<h2>检查项（").Append(run.Probes.Count).Append(" 项）</h2>");
        sb.Append("<table><tr><th>探针</th><th>目标</th><th>结论</th><th>传输</th><th>协议</th><th>耗时</th></tr>");
        foreach (var p in run.Probes)
        {
            var verdict = ConclusionEvaluator.Evaluate(p.Transport, p.Protocol);
            sb.Append("<tr><td>").Append(E(p.Parameters.ProbeType.ToString()))
              .Append("</td><td>").Append(E(p.Parameters.RequestedTarget))
              .Append("</td><td class='lv-").Append(E(verdict.Level.ToString())).Append("'>")
              .Append(E(LevelText(verdict.Level)))
              .Append("</td><td>").Append(E(p.Transport.ToString()))
              .Append("</td><td>").Append(E(p.Protocol.ToString()))
              .Append("</td><td>").Append(p.Elapsed is { } e ? $"{(int)e.TotalMilliseconds} ms" : "—")
              .Append("</td></tr>");
        }
        sb.Append("</table>");

        // 逐项详情
        sb.Append("<h2>逐项详情</h2>");
        foreach (var p in run.Probes)
        {
            var verdict = ConclusionEvaluator.Evaluate(p.Transport, p.Protocol);
            sb.Append("<details open><summary><b>").Append(E(p.Parameters.ProbeType.ToString()))
              .Append("</b> → ").Append(E(p.Parameters.RequestedTarget))
              .Append("（").Append(E(LevelText(verdict.Level))).Append("）</summary>");
            sb.Append("<p><b>参数：</b>").Append(E(JsonSerializer.Serialize(p.Parameters, JsonOpts))).Append("</p>");
            if (p.TransportDetail is not null)
                sb.Append("<p><b>传输：</b>").Append(E(RedactionService.Apply(p.TransportDetail, opt))).Append("</p>");
            if (p.ProtocolDetail is not null)
                sb.Append("<p><b>协议：</b>").Append(E(RedactionService.Apply(p.ProtocolDetail, opt))).Append("</p>");
            sb.Append("<p><b>结论说明：</b>").Append(E(verdict.Rationale)).Append("</p>");
            if (verdict.Limitations.Count > 0)
                sb.Append("<p><b>限制：</b>").Append(E(string.Join("；", verdict.Limitations))).Append("</p>");

            sb.Append("<h3>观察事实</h3><ol>");
            foreach (var obs in p.Observations)
            {
                sb.Append("<li><span class='muted'>").Append(E(obs.ObservedUtc.LocalDateTime.ToString("HH:mm:ss.fff")))
                  .Append("</span> ").Append(E(RedactionService.Apply(obs.Text, opt))).Append("</li>");
            }
            sb.Append("</ol></details>");
        }

        // 发现
        sb.Append("<h2>结论与建议</h2>");
        if (run.Findings.Count == 0)
        {
            sb.Append("<p class='muted'>（无显式发现）</p>");
        }
        foreach (var f in run.Findings)
        {
            sb.Append("<div class='finding lv-").Append(E(f.Level.ToString())).Append("'>");
            sb.Append("<p><b>[").Append(E(f.Severity.ToString())).Append("]</b> ")
              .Append(E(LevelText(f.Level))).Append("</p><ul>");
            foreach (var fact in f.ObservedFacts)
                sb.Append("<li>观察事实：").Append(E(RedactionService.Apply(fact, opt))).Append("</li>");
            if (f.Inference is not null)
                sb.Append("<li>可支持的推断：").Append(E(f.Inference)).Append("</li>");
            foreach (var lim in f.Limitations)
                sb.Append("<li>限制：").Append(E(lim)).Append("</li>");
            foreach (var step in f.NextSteps)
                sb.Append("<li>下一步：").Append(E(step)).Append("</li>");
            sb.Append("</ul></div>");
        }

        // 证据索引
        sb.Append("<h2>证据索引</h2><table><tr><th>种类</th><th>视角</th><th>采集时间(UTC)</th><th>文件</th><th>哈希</th><th>脱敏</th></tr>");
        foreach (var e in run.Evidences)
        {
            sb.Append("<tr><td>").Append(E(e.Kind.ToString()))
              .Append("</td><td>").Append(E(e.Side.ToString()))
              .Append("</td><td>").Append(E(e.CapturedUtc.ToString("yyyy-MM-dd HH:mm:ss")))
              .Append("</td><td>").Append(E(e.ArtifactPath ?? "—"))
              .Append("</td><td>").Append(E(e.ContentHash is { } h ? h[..16] + "…" : "—"))
              .Append("</td><td>").Append(E(e.Redaction.ToString()))
              .Append("</td></tr>");
        }
        sb.Append("</table>");

        // 附件
        if (run.Artifacts.Count > 0)
        {
            sb.Append("<h2>附件清单</h2><ul>");
            foreach (var a in run.Artifacts)
                sb.Append("<li>").Append(E(Path.GetFileName(a.AbsolutePath)))
                  .Append("（").Append(a.Size).Append(" 字节，SHA-256 ")
                  .Append(E(a.Sha256 is { } s ? s[..16] + "…" : "—")).Append("）</li>");
            sb.Append("</ul>");
            sb.Append("<p class='warn'>注意：导出的原始抓包（PCAPNG）可能包含业务数据；" +
                      "本报告的脱敏不适用于原始抓包文件。</p>");
        }

        sb.Append("<hr><p class='muted'>").Append(E(NetFlowInfo.ProductName))
          .Append(" v").Append(E(NetFlowInfo.Version))
          .Append("｜本报告完全离线生成。未检查项目不代表正常。</p>");
        sb.Append("</body></html>");
        return sb.ToString();
    }

    private static string LevelText(ConclusionLevel level) => level switch
    {
        ConclusionLevel.Pass => "通过",
        ConclusionLevel.Warning => "警告",
        ConclusionLevel.Fail => "失败",
        ConclusionLevel.Unconfirmed => "未确认",
        ConclusionLevel.NotChecked => "未检查",
        ConclusionLevel.Skipped => "跳过",
        ConclusionLevel.Canceled => "已取消",
        _ => level.ToString(),
    };

    private static string E(string s) =>
        System.Net.WebUtility.HtmlEncode(s);

    private static string Row(string k, string? v) =>
        $"<tr><th>{E(k)}</th><td>{E(v ?? "—")}</td></tr>";

    private const string OfflineCss = """
        body{font-family:'Segoe UI',system-ui,sans-serif;margin:24px auto;max-width:1100px;color:#1a1a1a;line-height:1.5}
        h1{font-size:1.5em;border-bottom:2px solid #2563eb;padding-bottom:8px}
        h2{font-size:1.15em;margin-top:24px}
        table{border-collapse:collapse;width:100%;margin:8px 0}
        th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;vertical-align:top}
        th{background:#f3f4f6}
        .muted{color:#6b7280;font-size:.92em}
        .warn{color:#92400e;background:#fef3c7;padding:8px 12px;border-radius:6px}
        .finding{border-left:4px solid #ddd;margin:12px 0;padding:8px 12px;background:#fafafa}
        .lv-Pass{border-color:#16a34a;color:#166534}
        .lv-Warning{border-color:#d97706;color:#92400e}
        .lv-Fail{border-color:#dc2626;color:#991b1b}
        .lv-Unconfirmed{border-color:#6b7280;color:#374151}
        .lv-NotChecked{border-color:#6b7280;color:#374151}
        details{margin:10px 0;padding:8px 12px;border:1px solid #e5e7eb;border-radius:8px}
        summary{cursor:pointer}
        code,pre{font-family:Consolas,monospace;font-size:.9em}
        """;
}
