namespace NetFlow.Application.Ai;

/// <summary>发送前的准备结果：已脱敏的内容（供用户预览确认）及还原映射。</summary>
public sealed record AiPreparedContext(string Text, AiAddressMasker? Masker);

/// <summary>AI 深入分析：按设置准备内容、调用 DeepSeek、在本地还原被替换的地址。</summary>
public sealed class AiAnalysisService(AppSettingsStore settings, DeepSeekClient? client = null)
{
    private readonly DeepSeekClient _client = client ?? new DeepSeekClient();

    /// <summary>是否已启用并配置完整。未配置时返回原因（用于引导用户去设置）。</summary>
    public bool IsReady(out string? reason)
    {
        var ai = settings.Current.Ai;
        if (!ai.Enabled) { reason = "AI 分析尚未启用，请到 设置 → AI 分析 中开启并填写 API Key"; return false; }
        if (!settings.HasApiKey || settings.TryGetApiKey() is null)
        {
            reason = "尚未配置有效的 API Key，请到 设置 → AI 分析 中填写";
            return false;
        }
        if (!DeepSeekClient.TryBuildEndpoint(ai.BaseUrl, out _, out var urlError)) { reason = urlError; return false; }
        reason = null;
        return true;
    }

    /// <summary>脱敏并按设置替换地址；返回的文本就是将要发送的全部上下文。</summary>
    public AiPreparedContext Prepare(string context)
    {
        var masker = settings.Current.Ai.MaskAddresses ? new AiAddressMasker() : null;
        return new AiPreparedContext(AiPromptBuilder.Sanitize(context, masker), masker);
    }

    public async Task<AiChatResult> AnalyzeAsync(
        AiPreparedContext prepared, string? question, CancellationToken ct = default)
    {
        var ai = settings.Current.Ai;
        var key = settings.TryGetApiKey();
        if (key is null) return AiChatResult.Fail("尚未配置有效的 API Key");

        var result = await _client.ChatAsync(new AiChatRequest
        {
            BaseUrl = ai.BaseUrl,
            Model = ai.Model,
            ApiKey = key,
            SystemPrompt = AiPromptBuilder.SystemPrompt,
            UserPrompt = AiPromptBuilder.BuildUserPrompt(prepared.Text, question),
            TimeoutSeconds = ai.TimeoutSeconds,
            ReasoningEffort = ai.ReasoningEffort,
        }, ct).ConfigureAwait(false);

        if (!result.Success || prepared.Masker is null) return result;
        return result with
        {
            Content = prepared.Masker.Unmask(result.Content),
            Reasoning = result.Reasoning is null ? null : prepared.Masker.Unmask(result.Reasoning),
        };
    }

    /// <summary>读取服务端可用模型列表（设置页“获取模型列表”）。</summary>
    public async Task<(IReadOnlyList<string> Models, string? Error)> ListModelsAsync(CancellationToken ct = default)
    {
        var ai = settings.Current.Ai;
        var key = settings.TryGetApiKey();
        if (key is null) return ([], "尚未配置有效的 API Key");
        return await _client.ListModelsAsync(ai.BaseUrl, key, Math.Min(ai.TimeoutSeconds, 60), ct)
            .ConfigureAwait(false);
    }

    /// <summary>设置页“测试连接”：发一条极短请求验证地址、Key 与模型名。</summary>
    public async Task<AiChatResult> TestConnectionAsync(CancellationToken ct = default)
    {
        var ai = settings.Current.Ai;
        var key = settings.TryGetApiKey();
        if (key is null) return AiChatResult.Fail("尚未配置有效的 API Key");
        return await _client.ChatAsync(new AiChatRequest
        {
            BaseUrl = ai.BaseUrl,
            Model = ai.Model,
            ApiKey = key,
            SystemPrompt = "你是连接测试助手。",
            UserPrompt = "请只回复两个字：正常",
            TimeoutSeconds = Math.Min(ai.TimeoutSeconds, 60),
            // 推理模型先输出推理内容再给答案，预算过小会没有正文而被误判为失败
            MaxTokens = 1024,
            ReasoningEffort = "low",
        }, ct).ConfigureAwait(false);
    }
}
