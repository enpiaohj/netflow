using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>TLS 证书信息快照。</summary>
public sealed record TlsCertificateInfo
{
    public required string Subject { get; init; }
    public required string Issuer { get; init; }
    public required string[] SubjectAlternativeNames { get; init; }
    public required DateTimeOffset NotBefore { get; init; }
    public required DateTimeOffset NotAfter { get; init; }
    public required string ThumbprintSha256 { get; init; }
    public required string SignatureAlgorithm { get; init; }
    public required int DaysRemaining { get; init; }
}

/// <summary>TLS 握手结果。</summary>
public sealed record TlsHandshakeInfo
{
    public required SslPolicyErrors ValidationErrors { get; init; }
    public required string[] ChainStatusTexts { get; init; }
    public required string ProtocolVersion { get; init; }
    public required string CipherSuite { get; init; }
    public TlsCertificateInfo? Certificate { get; init; }
}

/// <summary>
/// TLS 探针（设计文档 4.4）：指定 SNI/主机名，校验证书链、名称、有效期；
/// 失败时不悄悄关闭证书检查（结果如实呈现为失败事实）。
/// </summary>
public sealed class TlsProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.Tls;

    public override string DisplayName => "TLS 握手与证书";

    public async Task<ProbeRun> ExecuteAsync(
        IPAddress target, int port, string sniHostName, ProbeRequest request)
    {
        var run = NewRun(request);
        var timeout = request.Parameters.Timeout;
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        run.SourceAddress = request.SourceAddress?.ToString();
        run.AddObservation(Observation.Now(
            $"发起 TLS 握手：{target}:{port}（SNI={sniHostName}）", DisplayName));

        var family = target.AddressFamily;
        using var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp);
        if (request.SourceAddress is { } src)
            socket.Bind(new IPEndPoint(src, 0));

        TlsHandshakeInfo? handshake = null;
        var chainErrors = new List<string>();
        SslPolicyErrors validationErrors = SslPolicyErrors.None;
        X509Certificate2? remoteCert = null;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);

        var tcpSw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            await socket.ConnectAsync(new IPEndPoint(target, port), timeoutCts.Token)
                .ConfigureAwait(false);
            tcpSw.Stop();
            run.Stages = [new StageTiming
            {
                Stage = "TCP 连接",
                Duration = tcpSw.Elapsed,
                StartUtc = run.StartUtc,
            }];
            run.AddObservation(Observation.Now(
                $"TCP 连接成功（{(int)tcpSw.Elapsed.TotalMilliseconds} ms）", DisplayName));

            await using var network = new NetworkStream(socket, ownsSocket: false);
            await using var ssl = new SslStream(network, leaveInnerStreamOpen: true);

            var tlsSw = System.Diagnostics.Stopwatch.StartNew();
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = sniHostName,
                ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
                RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
                {
                    validationErrors = errors;
                    // 必须在回调内复制证书数据：原证书句柄在验证失败后会失效
                    remoteCert = cert switch
                    {
                        X509Certificate2 c2 => X509CertificateLoader.LoadCertificate(c2.GetRawCertData()),
                        X509Certificate c => X509CertificateLoader.LoadCertificate(c.GetRawCertData()),
                        _ => null,
                    };
                    if (chain is not null)
                    {
                        foreach (var status in chain.ChainStatus)
                            chainErrors.Add($"{status.Status}: {status.StatusInformation.Trim()}");
                    }
                    // 关键：验证失败必须如实报告。这里返回验证结果本身，
                    // 不返回 true 掩盖错误。
                    return errors == SslPolicyErrors.None;
                },
            };

            try
            {
                await ssl.AuthenticateAsClientAsync(options, timeoutCts.Token).ConfigureAwait(false);
                tlsSw.Stop();
                handshake = new TlsHandshakeInfo
                {
                    ValidationErrors = validationErrors,
                    ChainStatusTexts = [.. chainErrors],
                    ProtocolVersion = ssl.SslProtocol.ToString(),
                    CipherSuite = $"{ssl.NegotiatedCipherSuite}",
                    Certificate = ToCertInfo(remoteCert),
                };
                run.Stages = run.Stages.Append(new StageTiming
                {
                    Stage = "TLS 握手",
                    Duration = tlsSw.Elapsed,
                }).ToArray();

                run.Transport = TransportOutcome.Success;
                run.Protocol = ProtocolOutcome.Success;
                run.ProtocolDetail =
                    $"握手成功：{ssl.SslProtocol}，{ssl.NegotiatedCipherSuite}，证书验证通过";
                run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                DumpCert(run, handshake.Certificate!);
            }
            catch (AuthenticationException) when (validationErrors != SslPolicyErrors.None)
            {
                tlsSw.Stop();
                // 握手因证书验证失败而中止 —— 这是明确事实，不是网络故障
                run.Stages = run.Stages.Append(new StageTiming
                {
                    Stage = "TLS 握手",
                    Duration = tlsSw.Elapsed,
                }).ToArray();
                run.Transport = TransportOutcome.Success; // TCP 层成功
                run.Protocol = ProtocolOutcome.ProtocolError;
                run.ProtocolDetail =
                    $"TLS 握手在证书验证阶段中止：{validationErrors}。" +
                    "按策略不忽略证书错误继续。";
                run.ErrorCode = validationErrors.ToString();
                run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                foreach (var ce in chainErrors)
                    run.AddObservation(Observation.Now($"证书链状态：{ce}", DisplayName));
                if (remoteCert is not null)
                    DumpCert(run, ToCertInfo(remoteCert));
                FinishRun(run);
                return run;
            }

            FinishRun(run);
            return run;
        }
        catch (SocketException ex)
        {
            run.Transport = ClassifySocketError(ex.SocketErrorCode);
            run.ErrorCode = ex.SocketErrorCode.ToString();
            run.AddObservation(Observation.Now($"套接字错误：{ex.SocketErrorCode}", DisplayName));
            FinishRun(run);
            return run;
        }
        catch (AuthenticationException ex)
        {
            run.Transport = TransportOutcome.Success;
            run.Protocol = ProtocolOutcome.ProtocolError;
            run.ProtocolDetail = $"TLS 握手失败（非证书验证原因）：{ex.Message}";
            run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
            FinishRun(run);
            return run;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            run.Transport = TransportOutcome.Timeout;
            run.ErrorCode = "TLS_TIMEOUT";
            run.AddObservation(Observation.Now(
                $"超时：TLS 握手在 {timeout.TotalSeconds}s 内未完成", DisplayName));
            FinishRun(run);
            return run;
        }
        catch (OperationCanceledException)
        {
            run.State = ProbeState.Canceled;
            run.EndUtc = DateTimeOffset.UtcNow;
            return run;
        }
    }

    private static TlsCertificateInfo ToCertInfo(X509Certificate2? cert)
    {
        if (cert is null)
            throw new InvalidOperationException("无证书");
        var san = new List<string>();
        try
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509SubjectAlternativeNameExtension sanExt)
                {
                    san.AddRange(sanExt.EnumerateDnsNames());
                }
            }
        }
        catch
        {
            // SAN 扩展解析失败不影响证书信息呈现
        }

        var sha256 = SHA256.HashData(cert.RawData);
        return new TlsCertificateInfo
        {
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            SubjectAlternativeNames = [.. san],
            NotBefore = cert.NotBefore.ToUniversalTime(),
            NotAfter = cert.NotAfter.ToUniversalTime(),
            ThumbprintSha256 = Convert.ToHexString(sha256),
            SignatureAlgorithm = cert.SignatureAlgorithm.FriendlyName ?? "未知",
            DaysRemaining = (int)(cert.NotAfter - DateTimeOffset.Now).TotalDays,
        };
    }

    private void DumpCert(ProbeRun run, TlsCertificateInfo c)
    {
        run.AddObservation(Observation.Now(
            $"证书主题：{c.Subject}；颁发者：{c.Issuer}", DisplayName));
        run.AddObservation(Observation.Now(
            $"有效期：{c.NotBefore:yyyy-MM-dd} ~ {c.NotAfter:yyyy-MM-dd}（余 {c.DaysRemaining} 天）",
            DisplayName));
        if (c.SubjectAlternativeNames.Length > 0)
            run.AddObservation(Observation.Now(
                $"SAN：{string.Join("、", c.SubjectAlternativeNames)}", DisplayName));
        run.AddObservation(Observation.Now(
            $"指纹（SHA-256）：{c.ThumbprintSha256}", DisplayName));
    }
}
