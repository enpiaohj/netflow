using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>HTTP 探针选项。</summary>
public sealed record HttpProbeOptions
{
    /// <summary>使用 GET 而非 HEAD（设计文档：HEAD/GET 可选）。</summary>
    public bool UseGet { get; init; } = true;

    public bool FollowRedirects { get; init; } = true;

    public int MaxRedirects { get; init; } = 10;

    /// <summary>
    /// 使用系统代理。默认 false：内网诊断默认直连路径；
    /// 需要诊断"经代理路径"时显式开启（代理地址会作为观察记录）。
    /// </summary>
    public bool UseSystemProxy { get; init; }

    /// <summary>用户认为可接受的 HTTP 状态码集合（默认 2xx）。</summary>
    public IReadOnlySet<int> AcceptableStatusCodes { get; init; } =
        new HashSet<int>(Enumerable.Range(200, 100));

    /// <summary>忽略 TLS 证书错误。必须显式开启并记录（不悄悄忽略）。</summary>
    public bool DangerAcceptInvalidTls { get; init; }
}

/// <summary>
/// HTTP/HTTPS 探针（设计文档 4.4）：分阶段耗时（DNS/TCP/TLS+响应头）、重定向链、
/// 代理状态、用户定义可接受状态码。401/403 表示 HTTP 服务有应答，不代表业务可用。
/// </summary>
public sealed class HttpProbe : ProbeBase
{
    private readonly INameResolver _resolver;

    public HttpProbe(INameResolver? resolver = null)
    {
        _resolver = resolver ?? SystemNameResolver.Instance;
    }

    public override ProbeType Type => ProbeType.Http;

    public override string DisplayName => "HTTP/HTTPS";

    public async Task<ProbeRun> ExecuteAsync(
        Uri uri, ProbeRequest request, HttpProbeOptions? options = null)
    {
        var opt = options ?? new HttpProbeOptions();
        var run = NewRun(request);
        var ct = request.CancellationToken;
        var stages = new List<StageTiming>();

        run.AddObservation(Observation.Now(
            $"发起 {uri.Scheme.ToUpperInvariant()} 请求：{uri}（{(opt.UseGet ? "GET" : "HEAD")}）",
            DisplayName));

        // —— 阶段 1：DNS ——（IP 直连时跳过）
        IPAddress? resolvedIp = null;
        var host = uri.Host;
        if (IPAddress.TryParse(host, out var directIp))
        {
            resolvedIp = directIp;
            run.AddObservation(Observation.Now($"目标为 IP 地址，跳过解析：{host}", DisplayName));
            stages.Add(new StageTiming { Stage = "DNS 解析", Duration = TimeSpan.Zero });
        }
        else
        {
            var dnsSw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var addrs = await _resolver.ResolveAsync(host, ct).ConfigureAwait(false);
                dnsSw.Stop();
                resolvedIp = addrs.FirstOrDefault();
                run.ResolvedAddresses = addrs.Select(a => a.ToString()).ToArray();
                stages.Add(new StageTiming
                {
                    Stage = "DNS 解析",
                    Duration = dnsSw.Elapsed,
                    StartUtc = run.StartUtc,
                });
                run.AddObservation(Observation.Now(
                    $"解析 {host} → {string.Join("、", run.ResolvedAddresses)}（{(int)dnsSw.Elapsed.TotalMilliseconds} ms）",
                    DisplayName));
            }
            catch (ProbeNameResolutionException ex)
            {
                run.Transport = TransportOutcome.NameResolutionFailed;
                run.ErrorCode = "DNS_FAIL";
                run.AddObservation(Observation.Now(ex.Message, DisplayName));
                FinishRun(run);
                return run;
            }
        }

        // —— 代理观察 ——（GetProxy 返回目标自身 = 直连）
        var proxy = opt.UseSystemProxy ? HttpClient.DefaultProxy : new WebProxy();
        var proxyUri = proxy.GetProxy(uri);
        var viaProxy = proxyUri is not null && !proxyUri.Equals(uri);
        run.AddObservation(Observation.Now(
            viaProxy ? $"经代理 {proxyUri}" : "直连（未使用代理）", DisplayName,
            attributes: new Dictionary<string, string> { ["proxy"] = viaProxy ? proxyUri!.ToString() : "" }));

        // —— 重定向链 ——
        var current = uri;
        var redirectChain = new List<string>();
        ProtocolOutcome protocol = ProtocolOutcome.NotExecuted;
        string? protocolDetail = null;
        int acceptableHitStatus = 0;

        for (int hop = 0; hop <= (opt.FollowRedirects ? opt.MaxRedirects : 0); hop++)
        {
            ct.ThrowIfCancellationRequested();
            using var handler = BuildHandler(opt, resolvedIp, request.SourceAddress,
                _ => run.AddObservation(Observation.Now(
                    "TLS 证书验证未通过——按用户显式配置继续（已记录，未悄悄忽略）", DisplayName)));
            using var client = new HttpClient(handler);
            client.Timeout = request.Parameters.Timeout;

            using var msg = new HttpRequestMessage(
                opt.UseGet ? HttpMethod.Get : HttpMethod.Head, current);
            msg.Headers.UserAgent.ParseAdd(NetFlowInfo.UserAgent);

            var hopSw = System.Diagnostics.Stopwatch.StartNew();
            HttpResponseMessage resp;
            try
            {
                resp = await client.SendAsync(msg,
                    HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
                hopSw.Stop();
            }
            catch (HttpRequestException ex)
            {
                run.Transport = ex.HttpRequestError switch
                {
                    HttpRequestError.ConnectionError => TransportOutcome.Refused,
                    HttpRequestError.SecureConnectionError => TransportOutcome.Success,
                    _ => TransportOutcome.LocalError,
                };
                if (run.Transport == TransportOutcome.Success)
                {
                    // TLS 失败：TCP 可用，握手失败 —— 协议层错误
                    run.Protocol = ProtocolOutcome.ProtocolError;
                    run.ProtocolDetail = $"TLS 握手失败：{ex.Message}";
                    run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                    FinishRun(run);
                    return run;
                }
                run.ErrorCode = ex.HttpRequestError.ToString();
                run.AddObservation(Observation.Now($"连接失败：{ex.Message}", DisplayName));
                FinishRun(run);
                return run;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                run.Transport = TransportOutcome.Timeout;
                run.ErrorCode = "HTTP_TIMEOUT";
                run.AddObservation(Observation.Now(
                    $"超时：{current} 在 {request.Parameters.Timeout.TotalSeconds}s 内未返回响应头", DisplayName));
                FinishRun(run);
                return run;
            }

            using (resp)
            {
                acceptableHitStatus = (int)resp.StatusCode;
                var serverHeader = resp.Headers.Server.ToString();
                var contentType = resp.Content.Headers.ContentType?.ToString();
                stages.Add(new StageTiming
                {
                    Stage = hop == 0
                        ? "TLS 握手 + 响应头" + (uri.Scheme == "https" ? "" : "（响应头）")
                        : $"重定向 hop{hop}",
                    Duration = hopSw.Elapsed,
                    StartUtc = run.StartUtc,
                });

                run.AddObservation(Observation.Now(
                    $"HTTP {(int)resp.StatusCode} {resp.StatusCode}（{(int)hopSw.Elapsed.TotalMilliseconds} ms，" +
                    $"server={serverHeader}，content-type={contentType}）",
                    DisplayName,
                    attributes: new Dictionary<string, string>
                    {
                        ["status"] = ((int)resp.StatusCode).ToString(),
                        ["reason"] = resp.StatusCode.ToString(),
                    }));

                if (opt.AcceptableStatusCodes.Contains((int)resp.StatusCode))
                {
                    protocol = ProtocolOutcome.Success;
                    protocolDetail = $"按所选规则，状态码 {(int)resp.StatusCode} 可接受";
                    break;
                }

                // 401/403 等仍属"HTTP 服务有应答"
                protocol = ProtocolOutcome.ServiceError;
                protocolDetail =
                    $"状态码 {(int)resp.StatusCode} 不在可接受集合。这是 HTTP 服务的有效响应，非网络断开。";

                if (resp.StatusCode is System.Net.HttpStatusCode.MovedPermanently
                    or System.Net.HttpStatusCode.Found
                    or System.Net.HttpStatusCode.SeeOther
                    or System.Net.HttpStatusCode.TemporaryRedirect
                    or System.Net.HttpStatusCode.PermanentRedirect)
                {
                    var loc = resp.Headers.Location;
                    if (loc is null) break;
                    var next = loc.IsAbsoluteUri ? loc : new Uri(current, loc);
                    redirectChain.Add($"{current} → {(int)resp.StatusCode} → {next}");
                    current = next;
                    if (next.Scheme == "https" && uri.Scheme == "http" && resolvedIp is not null)
                    {
                        // 升级 https 后若原目标是 IP，SNI/名称验证按原值继续（记录事实）
                        run.AddObservation(Observation.Now(
                            "重定向至 HTTPS。若目标是 IP，证书名称验证可能失败（如实呈现，不自动忽略）",
                            DisplayName));
                    }
                    continue;
                }

                break;
            }
        }

        run.Transport = TransportOutcome.Success;
        run.Protocol = protocol;
        run.ProtocolDetail = protocolDetail;
        run.Stages = stages;
        foreach (var hop in redirectChain)
            run.AddObservation(Observation.Now($"重定向：{hop}", DisplayName));
        run.AddObservation(Observation.Now(
            $"最终状态：HTTP {acceptableHitStatus}。{protocolDetail}", DisplayName));

        FinishRun(run);
        return run;
    }

    private static SocketsHttpHandler BuildHandler(
        HttpProbeOptions opt, IPAddress? resolvedIp, IPAddress? source,
        Action<bool> onInvalidCertAccepted)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false, // 手动跟随以记录每一跳
            UseProxy = opt.UseSystemProxy,
        };

        handler.ConnectCallback = async (ctx, ct) =>
        {
            // 目标已在 DNS 阶段解析：直接用 IPEndPoint，避免二次解析
            Socket socket;
            if (resolvedIp is not null)
            {
                var endpoint = new IPEndPoint(resolvedIp, ctx.DnsEndPoint.Port);
                socket = new Socket(resolvedIp.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true,
                };
                if (source is not null)
                    socket.Bind(new IPEndPoint(source, 0));
                await socket.ConnectAsync(endpoint, ct).ConfigureAwait(false);
            }
            else
            {
                socket = new Socket(ctx.DnsEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true,
                };
                if (source is not null)
                    socket.Bind(new IPEndPoint(source, 0));
                await socket.ConnectAsync(ctx.DnsEndPoint, ct).ConfigureAwait(false);
            }
            return new NetworkStream(socket, ownsSocket: true);
        };

        if (opt.DangerAcceptInvalidTls)
        {
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, errors) =>
                {
                    if (errors != SslPolicyErrors.None)
                        onInvalidCertAccepted(true);
                    return true;
                },
            };
        }

        return handler;
    }
}
