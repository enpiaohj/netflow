using System.Text;
using System.Text.RegularExpressions;
using NetFlow.Domain;
using NetFlow.Reporting;

namespace NetFlow.Application.Ai;

/// <summary>
/// 地址脱敏映射：把文本中的 IPv4 地址替换为稳定的占位符（IP-1、IP-2…），
/// AI 返回结果后可在本地还原，第三方只能看到占位符。
/// </summary>
public sealed partial class AiAddressMasker
{
    private readonly Dictionary<string, string> _forward = [];
    private readonly Dictionary<string, string> _reverse = [];

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")]
    private static partial Regex Ipv4();

    [GeneratedRegex(@"IP-\d+\b")]
    private static partial Regex Placeholder();

    public string Mask(string text) => Ipv4().Replace(text, m =>
    {
        if (!_forward.TryGetValue(m.Value, out var token))
        {
            token = $"IP-{_forward.Count + 1}";
            _forward[m.Value] = token;
            _reverse[token] = m.Value;
        }
        return token;
    });

    /// <summary>把占位符还原为真实地址（仅本地显示使用）。</summary>
    public string Unmask(string text) =>
        _reverse.Count == 0 ? text : Placeholder().Replace(text, m => _reverse.TryGetValue(m.Value, out var ip) ? ip : m.Value);

    public int Count => _forward.Count;
}

/// <summary>AI 分析的提示词与上下文构造。发送内容统一经过脱敏，且有长度上限。</summary>
public static partial class AiPromptBuilder
{
    public const int MaxContextChars = 14000;

    public const string SystemPrompt = """
        你是资深的 Windows / 网络与服务诊断工程师，正在协助分析 NetFlow（网络与服务诊断工作台）生成的诊断证据。
        必须遵守：
        1. 只依据提供的证据推理，不编造证据中没有的事实；不确定时明确写“不确定”，并说明还缺什么信息。
        2. 严格区分“观察到的事实”和“推断”。
        3. 三条红线：UDP 无响应 = 未确认（既不代表端口开放，也不代表关闭）；本机收不到响应 ≠ 一定是防火墙丢包；TCP 端口可连接 ≠ 服务可用。
        4. 输出结构（Markdown，简洁）：
           ## 结论摘要（2–3 句）
           ## 关键证据
           ## 可能原因（按可能性从高到低，每条写出支持/反对的证据）
           ## 建议的下一步排查（可执行：具体命令或检查项，并注明在哪一端执行）
           ## 还需要补充的信息
        5. 使用简体中文；命令放在代码块中。
        6. 不要把“关闭防火墙/安全软件”作为解决办法；如需验证，只建议临时放行具体端口并在验证后恢复。
        """;

    [GeneratedRegex(@"(?i)\b(password|passwd|pwd|secret|token|api[-_]?key)\b\s*[=:]\s*\S+")]
    private static partial Regex InlineSecret();

    [GeneratedRegex(@"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}")]
    private static partial Regex BearerToken();

    /// <summary>
    /// 发送前处理：凭据类键值/Bearer 令牌一律打码（不可关闭）；可选把 IPv4 换成占位符；限制总长度。
    /// </summary>
    public static string Sanitize(string text, AiAddressMasker? addressMasker = null, int maxChars = MaxContextChars)
    {
        var result = RedactionService.Apply(text, new RedactionOptions { Enabled = true, MaskCredentialHeaders = true });
        result = InlineSecret().Replace(result, m => $"{m.Groups[1].Value}=********");
        result = BearerToken().Replace(result, "Bearer ********");
        if (addressMasker is not null) result = addressMasker.Mask(result);
        if (result.Length > maxChars)
            result = result[..maxChars] + "\n…（内容过长，已截断）";
        return result;
    }

    // ---- 上下文构造 ----

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

    private static string Clip(string text, int max) =>
        text.Length <= max ? text : text[..max] + "…";

    private static void AppendProbe(StringBuilder sb, int no, string name, ProbeRun p, int maxObservations)
    {
        var verdict = ConclusionEvaluator.Evaluate(p.Transport, p.Protocol);
        sb.Append(no).Append(". ").Append(name).Append(" [").Append(p.Parameters.ProbeType).Append(']')
          .Append(" 结论：").Append(LevelText(verdict.Level))
          .Append("｜传输层：").Append(p.Transport)
          .Append("｜协议层：").Append(p.Protocol)
          .Append("｜耗时：").Append(p.Elapsed is { } e ? $"{(int)e.TotalMilliseconds} ms" : "—");
        if (p.Parameters.Port is { } port) sb.Append("｜端口：").Append(port);
        if (!string.IsNullOrEmpty(p.SourceAddress)) sb.Append("｜源地址：").Append(p.SourceAddress);
        sb.AppendLine();
        sb.Append("   判定：").AppendLine(Clip(verdict.Rationale, 200));
        if (!string.IsNullOrEmpty(p.ProtocolDetail)) sb.Append("   协议说明：").AppendLine(Clip(p.ProtocolDetail, 200));
        foreach (var obs in p.Observations.Take(maxObservations))
            sb.Append("   - ").AppendLine(Clip(obs.Text, 220));
    }

    /// <summary>场景诊断（含系统发现）。</summary>
    public static string BuildRunContext(DiagnosisRun run)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# 场景诊断任务");
        sb.Append("目标：").Append(run.RequestedTarget);
        if (run.ResolvedAddresses.Count > 0) sb.Append("（解析为 ").Append(string.Join("、", run.ResolvedAddresses)).Append('）');
        sb.AppendLine();
        sb.Append("测试源：主机 ").Append(run.SourceHost)
          .Append("；网卡 ").Append(run.Adapter ?? "未知")
          .Append("；请求源地址 ").Append(run.RequestedSourceAddress ?? "未指定")
          .Append("；").Append(run.Elevated ? "已提权" : "普通权限").AppendLine();
        if (run.Scenario is { } sc)
            sb.Append("场景：").Append(sc.TemplateName).Append("（").Append(sc.Direction).AppendLine("）");
        if (run.TerminationReason is not null) sb.Append("终止原因：").AppendLine(run.TerminationReason);

        sb.AppendLine().AppendLine("## 检查项");
        var no = 1;
        foreach (var p in run.Probes)
        {
            var name = p.Parameters.Extra.TryGetValue("__stepName", out var n) ? n : p.Parameters.ProbeType.ToString();
            AppendProbe(sb, no++, name, p, maxObservations: 6);
        }

        if (run.Findings.Count > 0)
        {
            sb.AppendLine().AppendLine("## 系统已生成的发现");
            foreach (var f in run.Findings)
            {
                sb.Append('[').Append(f.Severity).Append("] ").AppendLine(LevelText(f.Level));
                foreach (var x in f.ObservedFacts) sb.Append("  事实：").AppendLine(Clip(x, 220));
                if (f.Inference is not null) sb.Append("  推断：").AppendLine(Clip(f.Inference, 220));
                foreach (var x in f.Limitations) sb.Append("  限制：").AppendLine(Clip(x, 200));
            }
        }
        return sb.ToString();
    }

    /// <summary>快速测试结果（一组探针）。</summary>
    public static string BuildProbeContext(
        string title, string target, string? sourceAddress, IReadOnlyList<ProbeRun> runs)
    {
        var sb = new StringBuilder();
        sb.Append("# ").AppendLine(title);
        sb.Append("目标：").AppendLine(target);
        sb.Append("源地址：").AppendLine(sourceAddress ?? "由系统路由选择");
        sb.AppendLine().AppendLine("## 检查项");
        var no = 1;
        foreach (var p in runs)
            AppendProbe(sb, no++, p.Parameters.ProbeType.ToString(), p, maxObservations: 10);
        return sb.ToString();
    }

    /// <summary>抓包分析：程序自动分析的异常摘要 + 数据包摘要行。</summary>
    public static string BuildCaptureContext(
        string title, string analysisText, IEnumerable<string> packetLines, int maxPacketLines = 150)
    {
        var sb = new StringBuilder();
        sb.Append("# ").AppendLine(title);
        sb.AppendLine("## 程序自动分析摘要").AppendLine(analysisText.Trim());
        sb.AppendLine().AppendLine("## 数据包摘要（时间 来源 → 目标 协议 信息，仅前若干条）");
        foreach (var line in packetLines.Take(maxPacketLines)) sb.AppendLine(Clip(line, 200));
        return sb.ToString();
    }

    /// <summary>用户在窗口中追加的问题（可选）。</summary>
    public static string BuildUserPrompt(string sanitizedContext, string? userQuestion)
    {
        var sb = new StringBuilder();
        sb.AppendLine("以下是诊断证据，请按要求分析：").AppendLine().AppendLine(sanitizedContext);
        if (!string.IsNullOrWhiteSpace(userQuestion))
            sb.AppendLine().Append("补充问题：").AppendLine(userQuestion.Trim());
        return sb.ToString();
    }
}
