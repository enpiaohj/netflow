using System.Net;
using System.Text;
using System.Text.Json;
using NetFlow.Application;
using NetFlow.Application.Ai;
using NetFlow.Domain;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>AI 分析：DeepSeek 请求/响应、发送内容脱敏、地址占位符与本地还原。全部离线，不访问网络。</summary>
public class AiTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public HttpRequestMessage? Last { get; private set; }

        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Last = request;
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
            return respond(request);
        }
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private static AiChatRequest Request(string baseUrl = "https://api.deepseek.com") => new()
    {
        BaseUrl = baseUrl, Model = "deepseek-chat", ApiKey = "sk-secret-key-0001",
        SystemPrompt = "sys", UserPrompt = "user",
    };

    // ---- 地址校验 ----

    [Theory]
    [InlineData("https://api.deepseek.com", "https://api.deepseek.com/chat/completions")]
    [InlineData("https://api.deepseek.com/", "https://api.deepseek.com/chat/completions")]
    [InlineData("https://gw.example.com/v1", "https://gw.example.com/v1/chat/completions")]
    [InlineData("http://localhost:8000/v1", "http://localhost:8000/v1/chat/completions")]
    public void 地址_https或本机回环http可用(string baseUrl, string expected)
    {
        Assert.True(DeepSeekClient.TryBuildEndpoint(baseUrl, out var endpoint, out var error));
        Assert.Null(error);
        Assert.Equal(expected, endpoint!.ToString());
    }

    [Theory]
    [InlineData("http://api.deepseek.com")]      // 明文传输 Key
    [InlineData("ftp://example.com")]
    [InlineData("not a url")]
    [InlineData("")]
    public void 地址_非https远程地址被拒绝(string baseUrl)
    {
        Assert.False(DeepSeekClient.TryBuildEndpoint(baseUrl, out var endpoint, out var error));
        Assert.Null(endpoint);
        Assert.NotNull(error);
    }

    // ---- 模型列表 ----

    [Fact]
    public void 模型列表_解析官方返回()
    {
        var ids = DeepSeekClient.ParseModelList(
            """{"object":"list","data":[{"id":"deepseek-flash","name":"DeepSeek-V4.1-Flash"},{"id":"deepseek-v4-pro"},{"foo":1}]}""");
        Assert.Equal(["deepseek-flash", "deepseek-v4-pro"], ids);
        Assert.Empty(DeepSeekClient.ParseModelList("not json"));
        Assert.Empty(DeepSeekClient.ParseModelList("""{"data":"x"}"""));
    }

    [Theory]
    [InlineData("https://api.deepseek.com", "https://api.deepseek.com/models")]
    [InlineData("https://api.deepseek.com/v1/", "https://api.deepseek.com/v1/models")]
    public void 模型列表_地址(string baseUrl, string expected)
    {
        Assert.True(DeepSeekClient.TryBuildModelsEndpoint(baseUrl, out var endpoint, out _));
        Assert.Equal(expected, endpoint!.ToString());
    }

    [Fact]
    public async Task 模型列表_GET带Bearer头_错误给出中文原因()
    {
        var ok = new StubHandler(_ => Json(HttpStatusCode.OK, """{"data":[{"id":"deepseek-flash"}]}"""));
        var (models, error) = await new DeepSeekClient(ok).ListModelsAsync("https://api.deepseek.com", "sk-1", 30);
        Assert.Null(error);
        Assert.Equal(["deepseek-flash"], models);
        Assert.Equal(HttpMethod.Get, ok.Last!.Method);
        Assert.Equal("Bearer", ok.Last.Headers.Authorization!.Scheme);

        var unauthorized = new StubHandler(_ => Json(HttpStatusCode.Unauthorized, """{"error":{"message":"bad key"}}"""));
        var (none, err) = await new DeepSeekClient(unauthorized).ListModelsAsync("https://api.deepseek.com", "sk-1", 30);
        Assert.Empty(none);
        Assert.Contains("401", err);
    }

    [Fact]
    public void 请求_推理强度仅在设置时发送()
    {
        using var without = JsonDocument.Parse(DeepSeekClient.BuildRequestJson(Request()));
        Assert.False(without.RootElement.TryGetProperty("reasoning_effort", out _));

        using var withEffort = JsonDocument.Parse(DeepSeekClient.BuildRequestJson(Request() with { ReasoningEffort = "low" }));
        Assert.Equal("low", withEffort.RootElement.GetProperty("reasoning_effort").GetString());

        using var blank = JsonDocument.Parse(DeepSeekClient.BuildRequestJson(Request() with { ReasoningEffort = " " }));
        Assert.False(blank.RootElement.TryGetProperty("reasoning_effort", out _));
    }

    [Fact]
    public void 响应_达到输出上限时标记截断_推理耗尽无正文时给出可操作提示()
    {
        var truncated = DeepSeekClient.ParseResponse(HttpStatusCode.OK,
            """{"choices":[{"finish_reason":"length","message":{"content":"写到一半"}}]}""");
        Assert.True(truncated.Success);
        Assert.True(truncated.Truncated);

        var complete = DeepSeekClient.ParseResponse(HttpStatusCode.OK,
            """{"choices":[{"finish_reason":"stop","message":{"content":"完整"}}]}""");
        Assert.False(complete.Truncated);

        var exhausted = DeepSeekClient.ParseResponse(HttpStatusCode.OK,
            """{"choices":[{"finish_reason":"length","message":{"content":"","reasoning_content":"想了很久"}}]}""");
        Assert.False(exhausted.Success);
        Assert.Contains("推理强度", exhausted.Error);
    }

    [Fact]
    public void 请求_默认输出预算足够容纳推理内容()
    {
        // DeepSeek 现行模型会先输出推理内容；预算过小会没有正文
        Assert.True(Request().MaxTokens >= 16384);
        Assert.Equal("deepseek-flash", AiSettings.DefaultModel);
    }

    // ---- 请求 ----

    [Fact]
    public async Task 请求_Bearer头与JSON体_Key不进入请求体()
    {
        var handler = new StubHandler(_ => Json(HttpStatusCode.OK,
            """{"choices":[{"message":{"content":"分析结果"}}],"usage":{"prompt_tokens":10,"completion_tokens":5}}"""));
        var result = await new DeepSeekClient(handler).ChatAsync(Request());

        Assert.True(result.Success);
        Assert.Equal("分析结果", result.Content);
        Assert.Equal(10, result.PromptTokens);
        Assert.Equal(5, result.CompletionTokens);

        Assert.Equal("https://api.deepseek.com/chat/completions", handler.Last!.RequestUri!.ToString());
        Assert.Equal("Bearer", handler.Last.Headers.Authorization!.Scheme);
        Assert.Equal("sk-secret-key-0001", handler.Last.Headers.Authorization.Parameter);

        using var body = JsonDocument.Parse(handler.LastBody!);
        Assert.Equal("deepseek-chat", body.RootElement.GetProperty("model").GetString());
        Assert.False(body.RootElement.GetProperty("stream").GetBoolean());
        Assert.Equal(2, body.RootElement.GetProperty("messages").GetArrayLength());
        Assert.DoesNotContain("sk-secret-key-0001", handler.LastBody);
    }

    [Fact]
    public async Task 未配置Key时不发请求()
    {
        var handler = new StubHandler(_ => throw new InvalidOperationException("不应发出请求"));
        var result = await new DeepSeekClient(handler).ChatAsync(Request() with { ApiKey = " " });

        Assert.False(result.Success);
        Assert.Contains("API Key", result.Error);
        Assert.Null(handler.Last);
    }

    [Fact]
    public async Task 非法地址不发请求()
    {
        var handler = new StubHandler(_ => throw new InvalidOperationException("不应发出请求"));
        var result = await new DeepSeekClient(handler).ChatAsync(Request("http://evil.example.com"));

        Assert.False(result.Success);
        Assert.Contains("https", result.Error);
        Assert.Null(handler.Last);
    }

    // ---- 响应 ----

    [Theory]
    [InlineData(401, "API Key")]
    [InlineData(402, "余额")]
    [InlineData(429, "频繁")]
    [InlineData(500, "暂时不可用")]
    [InlineData(404, "地址")]
    public void 响应_HTTP错误给出中文原因(int status, string expectedFragment)
    {
        var result = DeepSeekClient.ParseResponse((HttpStatusCode)status, """{"error":{"message":"detail-x"}}""");

        Assert.False(result.Success);
        Assert.Contains(expectedFragment, result.Error);
        Assert.Contains("detail-x", result.Error); // 附服务端简短说明
    }

    [Fact]
    public void 响应_非JSON错误页不展示原文()
    {
        var result = DeepSeekClient.ParseResponse(HttpStatusCode.BadGateway, "<html><body>Bad Gateway page...</body></html>");

        Assert.False(result.Success);
        Assert.DoesNotContain("<html>", result.Error);
    }

    [Fact]
    public void 响应_推理模型返回思考过程()
    {
        var result = DeepSeekClient.ParseResponse(HttpStatusCode.OK,
            """{"choices":[{"message":{"content":"最终答案","reasoning_content":"推理过程"}}]}""");

        Assert.True(result.Success);
        Assert.Equal("最终答案", result.Content);
        Assert.Equal("推理过程", result.Reasoning);
    }

    [Theory]
    [InlineData("""{"choices":[]}""")]
    [InlineData("""{"choices":[{"message":{"content":"  "}}]}""")]
    [InlineData("not json")]
    [InlineData("""{"foo":1}""")]
    public void 响应_空内容或格式异常_失败而不抛异常(string body)
    {
        var result = DeepSeekClient.ParseResponse(HttpStatusCode.OK, body);
        Assert.False(result.Success);
        Assert.False(string.IsNullOrEmpty(result.Error));
    }

    // ---- 脱敏 ----

    [Fact]
    public void 脱敏_凭据键值与Bearer令牌被打码()
    {
        var text = "登录 password=Abc123!x 失败\nAuthorization: Bearer abcdefghijkl1234\nheader token: xyz789\n正常文本 keep";
        var clean = AiPromptBuilder.Sanitize(text);

        Assert.DoesNotContain("Abc123", clean);
        Assert.DoesNotContain("abcdefghijkl1234", clean);
        Assert.DoesNotContain("xyz789", clean);
        Assert.Contains("正常文本 keep", clean);
    }

    [Fact]
    public void 脱敏_过长内容被截断并说明()
    {
        var clean = AiPromptBuilder.Sanitize(new string('a', 500), maxChars: 100);
        Assert.StartsWith(new string('a', 100), clean);
        Assert.Contains("已截断", clean);
    }

    [Fact]
    public void 地址占位符_稳定映射_可本地还原_第三方看不到真实地址()
    {
        var masker = new AiAddressMasker();
        var masked = masker.Mask("192.168.10.100 → 192.168.10.11:445，再次 192.168.10.11 与 10.0.0.5");

        Assert.DoesNotContain("192.168", masked);
        Assert.Equal("IP-1 → IP-2:445，再次 IP-2 与 IP-3", masked);
        Assert.Equal(3, masker.Count);

        var answer = "请检查 IP-2 的 445 端口，并对比 IP-1 到 IP-3 的路径";
        Assert.Equal("请检查 192.168.10.11 的 445 端口，并对比 192.168.10.100 到 10.0.0.5 的路径", masker.Unmask(answer));
    }

    [Fact]
    public void 地址占位符_不误伤非IP的点分数字()
    {
        var masker = new AiAddressMasker();
        Assert.Equal("版本 1.2.3 与 999.1.1.1 不是地址", masker.Mask("版本 1.2.3 与 999.1.1.1 不是地址"));
    }

    // ---- 上下文 ----

    private static DiagnosisRun SampleRun()
    {
        var run = new DiagnosisRun
        {
            SourceHost = "PC01", RequestedTarget = "dc01.corp.local", AppVersion = "0.0.0",
            Adapter = "以太网", RequestedSourceAddress = "192.168.10.100",
            ResolvedAddresses = ["192.168.10.11"],
        };
        var probe = new ProbeRun
        {
            RunId = run.Id,
            Parameters = new ProbeParameters
            {
                ProbeType = ProbeType.TcpConnect, RequestedTarget = "dc01", Port = 445,
                Extra = new Dictionary<string, string> { ["__stepName"] = "SMB 端口" },
            },
            Transport = TransportOutcome.Timeout,
            SourceAddress = "192.168.10.100",
        };
        probe.AddObservation(Observation.Now("连接超时 password=Sup3rS3cret", "TCP"));
        run.Probes.Add(probe);
        return run;
    }

    [Fact]
    public void 场景上下文_包含关键事实_经脱敏后不含密码()
    {
        var context = AiPromptBuilder.BuildRunContext(SampleRun());

        Assert.Contains("dc01.corp.local", context);
        Assert.Contains("SMB 端口", context);
        Assert.Contains("端口：445", context);
        Assert.Contains("请求源地址 192.168.10.100", context);

        var clean = AiPromptBuilder.Sanitize(context);
        Assert.DoesNotContain("Sup3rS3cret", clean);
        Assert.Contains("SMB 端口", clean);
    }

    [Fact]
    public void 系统提示词_包含三条红线与输出结构()
    {
        var p = AiPromptBuilder.SystemPrompt;
        Assert.Contains("UDP 无响应", p);
        Assert.Contains("防火墙丢包", p);
        Assert.Contains("服务可用", p);
        Assert.Contains("下一步排查", p);
    }

    [Fact]
    public void 用户提示词_附带补充问题()
    {
        var text = AiPromptBuilder.BuildUserPrompt("CTX", "为什么 445 不通？");
        Assert.Contains("CTX", text);
        Assert.Contains("补充问题：为什么 445 不通？", text);
        Assert.DoesNotContain("补充问题", AiPromptBuilder.BuildUserPrompt("CTX", "  "));
    }

    // ---- 服务 ----

    [Fact]
    public async Task 服务_准备内容按设置替换地址_结果在本地还原()
    {
        var store = new AppSettingsStore(repository: null);
        await store.SetApiKeyAsync("sk-abc");
        await store.UpdateAsync(s => s with { Ai = s.Ai with { Enabled = true, MaskAddresses = true } });

        var handler = new StubHandler(_ => Json(HttpStatusCode.OK,
            """{"choices":[{"message":{"content":"IP-1 的 445 端口不通"}}]}"""));
        var service = new AiAnalysisService(store, new DeepSeekClient(handler));

        Assert.True(service.IsReady(out _));
        var prepared = service.Prepare("目标 10.1.2.3 端口 445");
        Assert.DoesNotContain("10.1.2.3", prepared.Text);

        var result = await service.AnalyzeAsync(prepared, question: null);
        Assert.True(result.Success);
        Assert.Equal("10.1.2.3 的 445 端口不通", result.Content); // 本地还原
        Assert.DoesNotContain("10.1.2.3", handler.LastBody);     // 发出的请求里没有真实地址
    }

    [Fact]
    public async Task 服务_未启用或未配置Key时给出引导()
    {
        var store = new AppSettingsStore(repository: null);
        var service = new AiAnalysisService(store);

        Assert.False(service.IsReady(out var r1));
        Assert.Contains("尚未启用", r1);

        await store.UpdateAsync(s => s with { Ai = s.Ai with { Enabled = true } });
        Assert.False(service.IsReady(out var r2));
        Assert.Contains("API Key", r2);

        await store.SetApiKeyAsync("sk-abc");
        Assert.True(service.IsReady(out _));

        await store.UpdateAsync(s => s with { Ai = s.Ai with { BaseUrl = "http://remote.example.com" } });
        Assert.False(service.IsReady(out var r3));
        Assert.Contains("https", r3);
    }
}
