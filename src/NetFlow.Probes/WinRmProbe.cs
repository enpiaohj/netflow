using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>
/// WinRM 探针（设计文档 4.4）：WS-Man Identify（HTTP 5985 / HTTPS 5986）最小化握手。
/// 不声称登录或授权成功。
/// </summary>
public sealed class WinRmProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.WinRm;

    public override string DisplayName => "WinRM";

    public async Task<ProbeRun> ExecuteAsync(IPAddress target, int port, bool useHttps, ProbeRequest request)
    {
        var run = NewRun(request);
        var ct = request.CancellationToken;
        run.ResolvedAddresses = [target.ToString()];
        run.AddObservation(Observation.Now(
            $"WinRM 探测：{(useHttps ? "https" : "http")}://{target}:{port}/wsman", DisplayName));

        // 先 TCP（独立记录传输层）
        var tcpRun = await new TcpConnectProbe().ExecuteAsync(target, port, request)
            .ConfigureAwait(false);
        run.Transport = tcpRun.Transport;
        run.Stages = tcpRun.Stages;
        run.SourceAddress = tcpRun.SourceAddress;
        foreach (var obs in tcpRun.Observations)
            run.AddObservation(obs with { Source = DisplayName });

        if (tcpRun.Transport is not TransportOutcome.Success)
        {
            FinishRun(run);
            return run;
        }

        // WS-Man Identify SOAP
        const string envelope = """
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                        xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
                        xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
              <s:Header>
                <a:To>/{TO}</a:To>
                <a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
                <a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
                <w:ResourceURI>http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd</w:ResourceURI>
                <a:MessageID>uuid:{MID}</a:MessageID>
              </s:Header>
              <s:Body/>
            </s:Envelope>
            """;
        var body = envelope
            .Replace("{TO}", $"{target}:{port}")
            .Replace("{MID}", Guid.NewGuid().ToString());

        try
        {
            using var handler = new HttpClientHandler();
            if (useHttps)
            {
                // WinRM 常用自签名证书：诊断探针记录验证失败但不中止事实采集，
                // 由 TLS 探针提供正式证书验证结论
                handler.ServerCertificateCustomValidationCallback = (_, _, _, err) =>
                {
                    if (err != System.Net.Security.SslPolicyErrors.None)
                        run.AddObservation(Observation.Now(
                            "HTTPS 证书验证未通过（已记录；正式验证结论见 TLS 探针）", DisplayName));
                    return true;
                };
            }
            using var client = new HttpClient(handler) { Timeout = request.Parameters.Timeout };
            using var msg = new HttpRequestMessage(HttpMethod.Post,
                $"{(useHttps ? "https" : "http")}://{target}:{port}/wsman")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/soap+xml"),
            };
            msg.Headers.Add("SOAPAction", @"""http://schemas.xmlsoap.org/ws/2004/09/transfer/Get""");

            var sw = System.Diagnostics.Stopwatch.StartNew();
            using var resp = await client.SendAsync(msg, ct).ConfigureAwait(false);
            sw.Stop();

            var text = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            string? product = null;
            try
            {
                var doc = XDocument.Parse(text);
                product = doc.Descendants()
                    .FirstOrDefault(e => e.Name.LocalName == "Product")?.Value;
            }
            catch
            {
                // 非 XML 响应如实记录
            }

            run.Protocol = resp.IsSuccessStatusCode && product is not null
                ? ProtocolOutcome.Success
                : resp.IsSuccessStatusCode
                    ? ProtocolOutcome.ProtocolError
                    : ProtocolOutcome.ServiceError;
            run.ProtocolDetail = resp.IsSuccessStatusCode
                ? $"WS-Man Identify 成功（{(int)sw.Elapsed.TotalMilliseconds} ms）：{product ?? "响应无 Product 字段"}。仅握手成功，不代表授权可用。"
                : $"HTTP {(int)resp.StatusCode}（服务有响应，按预期规则判定）";
            run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName,
                new Dictionary<string, string> { ["status"] = ((int)resp.StatusCode).ToString() }));

            FinishRun(run);
            return run;
        }
        catch (HttpRequestException ex)
        {
            run.Protocol = ProtocolOutcome.ProtocolError;
            run.ProtocolDetail = $"HTTP 层失败：{ex.Message}";
            run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
            FinishRun(run);
            return run;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            run.Protocol = ProtocolOutcome.NoResponse;
            run.ErrorCode = "WINRM_TIMEOUT";
            run.AddObservation(Observation.Now(
                $"超时：WS-Man Identify 在 {request.Parameters.Timeout.TotalSeconds}s 内未响应", DisplayName));
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
}
