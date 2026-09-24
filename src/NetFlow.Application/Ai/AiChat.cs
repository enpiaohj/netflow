using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace NetFlow.Application.Ai;

/// <summary>一次对话请求（OpenAI 兼容的 chat/completions）。</summary>
public sealed record AiChatRequest
{
    public required string BaseUrl { get; init; }

    public required string Model { get; init; }

    public required string ApiKey { get; init; }

    public required string SystemPrompt { get; init; }

    public required string UserPrompt { get; init; }

    public int TimeoutSeconds { get; init; } = 120;

    /// <summary>
    /// 输出上限（含推理过程）。DeepSeek 现行模型会先输出推理内容再给答案，
    /// 预算过小会被推理耗尽而没有正文，因此默认取较大值。
    /// </summary>
    public int MaxTokens { get; init; } = 16384;

    /// <summary>推理强度（low / high / max）；null 或空 = 不发送该参数。</summary>
    public string? ReasoningEffort { get; init; }

    public double Temperature { get; init; } = 0.3;
}

/// <summary>对话结果。失败时 Error 为可直接展示的中文说明（不含 Key 与请求内容）。</summary>
public sealed record AiChatResult
{
    public bool Success { get; init; }

    public string Content { get; init; } = "";

    /// <summary>推理模型（deepseek-reasoner）返回的思考过程，可为空。</summary>
    public string? Reasoning { get; init; }

    public string? Error { get; init; }

    public int? PromptTokens { get; init; }

    public int? CompletionTokens { get; init; }

    /// <summary>因达到输出上限（finish_reason = length）而被截断：正文可能不完整。</summary>
    public bool Truncated { get; init; }

    public static AiChatResult Fail(string error) => new() { Success = false, Error = error };
}

/// <summary>
/// DeepSeek 客户端（chat/completions，非流式）。请求/响应处理为纯函数，便于离线测试；
/// API Key 只放在 Authorization 头，不进入日志、异常与错误文本。
/// </summary>
public sealed class DeepSeekClient
{
    private readonly HttpMessageHandler? _handler;

    /// <param name="handler">测试注入；生产环境为 null（使用系统代理设置的默认处理器）。</param>
    public DeepSeekClient(HttpMessageHandler? handler = null) => _handler = handler;

    /// <summary>
    /// 校验 API 地址：必须是 https（本机回环地址可用 http，便于本地网关调试），
    /// 避免 Key 经明文传输。
    /// </summary>
    public static bool TryBuildEndpoint(string baseUrl, out Uri? endpoint, out string? error)
    {
        endpoint = null;
        if (!Uri.TryCreate(baseUrl?.Trim(), UriKind.Absolute, out var uri))
        {
            error = "API 地址格式无效";
            return false;
        }
        var isLoopbackHttp = uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback;
        if (uri.Scheme != Uri.UriSchemeHttps && !isLoopbackHttp)
        {
            error = "API 地址必须使用 https（仅本机回环地址允许 http）";
            return false;
        }
        endpoint = new Uri(uri.ToString().TrimEnd('/') + "/chat/completions");
        error = null;
        return true;
    }

    /// <summary>模型列表接口地址：{API 地址}/models。</summary>
    public static bool TryBuildModelsEndpoint(string baseUrl, out Uri? endpoint, out string? error)
    {
        if (!TryBuildEndpoint(baseUrl, out var chat, out error))
        {
            endpoint = null;
            return false;
        }
        endpoint = new Uri(chat!.ToString().Replace("/chat/completions", "/models"));
        return true;
    }

    /// <summary>解析 GET /models 响应，返回模型 ID 列表（按返回顺序）。</summary>
    public static IReadOnlyList<string> ParseModelList(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                return [];
            return [.. data.EnumerateArray()
                .Select(m => m.TryGetProperty("id", out var id) ? id.GetString() : null)
                .Where(id => !string.IsNullOrWhiteSpace(id))!];
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>读取服务端可用模型列表（用于设置页下拉，避免写死会过期的模型名）。</summary>
    public async Task<(IReadOnlyList<string> Models, string? Error)> ListModelsAsync(
        string baseUrl, string apiKey, int timeoutSeconds, CancellationToken ct = default)
    {
        if (!TryBuildModelsEndpoint(baseUrl, out var endpoint, out var urlError)) return ([], urlError);
        if (string.IsNullOrWhiteSpace(apiKey)) return ([], "尚未配置 API Key");

        using var http = _handler is null ? new HttpClient() : new HttpClient(_handler, disposeHandler: false);
        http.Timeout = TimeSpan.FromSeconds(Math.Clamp(timeoutSeconds, 10, 120));
        using var message = new HttpRequestMessage(HttpMethod.Get, endpoint);
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        try
        {
            using var response = await http.SendAsync(message, ct).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                return ([], ParseResponse(response.StatusCode, body).Error);
            var models = ParseModelList(body);
            return models.Count > 0 ? (models, null) : ([], "服务端未返回可用模型");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return ([], "已取消");
        }
        catch (TaskCanceledException)
        {
            return ([], "请求超时");
        }
        catch (HttpRequestException ex)
        {
            return ([], $"无法连接 AI 服务：{ex.InnerException?.Message ?? ex.Message}");
        }
    }

    public static string BuildRequestJson(AiChatRequest request)
    {
        var body = new Dictionary<string, object>
        {
            ["model"] = request.Model,
            ["messages"] = new object[]
            {
                new { role = "system", content = request.SystemPrompt },
                new { role = "user", content = request.UserPrompt },
            },
            ["stream"] = false,
            ["max_tokens"] = request.MaxTokens,
            ["temperature"] = request.Temperature,
        };
        if (!string.IsNullOrWhiteSpace(request.ReasoningEffort))
            body["reasoning_effort"] = request.ReasoningEffort.Trim();
        return JsonSerializer.Serialize(body);
    }

    /// <summary>解析响应。HTTP 失败时按状态码给出中文原因，并附服务端返回的简短说明。</summary>
    public static AiChatResult ParseResponse(HttpStatusCode status, string body)
    {
        if ((int)status is < 200 or >= 300)
        {
            var hint = (int)status switch
            {
                400 => "请求参数有误（400）",
                401 => "API Key 无效或已失效（401），请在设置中重新填写",
                402 => "账户余额不足（402），请充值后重试",
                403 => "没有权限访问该模型或接口（403）",
                404 => "接口地址不存在（404），请检查 API 地址与模型名",
                422 => "请求参数无法处理（422）",
                429 => "请求过于频繁或超出限额（429），请稍后重试",
                >= 500 => $"服务端暂时不可用（{(int)status}），请稍后重试",
                _ => $"请求失败（HTTP {(int)status}）",
            };
            var detail = ExtractServerMessage(body);
            return AiChatResult.Fail(detail.Length > 0 ? $"{hint}：{detail}" : hint);
        }

        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (!root.TryGetProperty("choices", out var choices) || choices.GetArrayLength() == 0)
                return AiChatResult.Fail("响应中没有内容（choices 为空）");

            var message = choices[0].GetProperty("message");
            var content = message.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.String
                ? c.GetString() ?? "" : "";
            var reasoning = message.TryGetProperty("reasoning_content", out var r) && r.ValueKind == JsonValueKind.String
                ? r.GetString() : null;

            int? promptTokens = null, completionTokens = null;
            if (root.TryGetProperty("usage", out var usage))
            {
                if (usage.TryGetProperty("prompt_tokens", out var p) && p.TryGetInt32(out var pt)) promptTokens = pt;
                if (usage.TryGetProperty("completion_tokens", out var q) && q.TryGetInt32(out var ct)) completionTokens = ct;
            }

            var truncated = choices[0].TryGetProperty("finish_reason", out var fr)
                && fr.ValueKind == JsonValueKind.String && fr.GetString() == "length";

            if (string.IsNullOrWhiteSpace(content))
            {
                return AiChatResult.Fail(truncated
                    ? "输出额度被推理过程耗尽，没有生成正文：请在设置中降低推理强度后重试"
                    : "模型返回了空内容");
            }

            return new AiChatResult
            {
                Success = true, Content = content, Reasoning = reasoning,
                PromptTokens = promptTokens, CompletionTokens = completionTokens,
                Truncated = truncated,
            };
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            return AiChatResult.Fail("无法解析服务端响应（格式不符合预期）");
        }
    }

    private static string ExtractServerMessage(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("error", out var err))
            {
                var msg = err.ValueKind == JsonValueKind.Object && err.TryGetProperty("message", out var m)
                    ? m.GetString() : err.ValueKind == JsonValueKind.String ? err.GetString() : null;
                if (!string.IsNullOrWhiteSpace(msg)) return msg.Length > 200 ? msg[..200] + "…" : msg;
            }
        }
        catch (JsonException)
        {
            // 非 JSON 响应体（网关错误页等）不展示，避免把整页 HTML 塞进提示
        }
        return "";
    }

    public async Task<AiChatResult> ChatAsync(AiChatRequest request, CancellationToken ct = default)
    {
        if (!TryBuildEndpoint(request.BaseUrl, out var endpoint, out var urlError))
            return AiChatResult.Fail(urlError!);
        if (string.IsNullOrWhiteSpace(request.ApiKey))
            return AiChatResult.Fail("尚未配置 API Key，请先到 设置 → AI 分析 中填写");

        using var http = _handler is null ? new HttpClient() : new HttpClient(_handler, disposeHandler: false);
        http.Timeout = TimeSpan.FromSeconds(Math.Clamp(request.TimeoutSeconds, 10, 600));
        using var message = new HttpRequestMessage(HttpMethod.Post, endpoint)
        {
            Content = new StringContent(BuildRequestJson(request), Encoding.UTF8, "application/json"),
        };
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", request.ApiKey);

        try
        {
            using var response = await http.SendAsync(message, ct).ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return ParseResponse(response.StatusCode, body);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return AiChatResult.Fail("已取消");
        }
        catch (TaskCanceledException)
        {
            return AiChatResult.Fail($"请求超时（{request.TimeoutSeconds} 秒未返回），可在设置中调大超时或换用更快的模型");
        }
        catch (HttpRequestException ex)
        {
            // 只给出底层原因（DNS/连接/证书），绝不带请求内容或头
            return AiChatResult.Fail($"无法连接 AI 服务：{ex.InnerException?.Message ?? ex.Message}");
        }
    }
}
