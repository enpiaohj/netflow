using System.Buffers.Binary;
using System.Data;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Data.SqlClient;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>
/// SQL Server 探针（设计文档 4.4）：UDP 1434 实例发现 → 返回端口 TCP → 可选 TLS/认证。
/// 实例发现与数据库连接分步呈现；固定端口配置无需依赖 Browser。
/// </summary>
public sealed class SqlServerProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.SqlServer;

    public override string DisplayName => "SQL Server";

    /// <summary>
    /// 实例发现（SSRP，UDP 1434，请求字节 0x02）。
    /// </summary>
    public async Task<ProbeRun> ExecuteAsync(
        IPAddress target, string? instanceName, int? fixedPort,
        NetworkCredential? sqlCredential, bool tryLogin, ProbeRequest request)
    {
        var run = NewRun(request);
        var ct = request.CancellationToken;
        var timeout = request.Parameters.Timeout;
        run.ResolvedAddresses = [target.ToString()];
        var stages = new List<StageTiming>();

        int port;
        if (fixedPort is { } fp)
        {
            port = fp;
            run.AddObservation(Observation.Now(
                $"使用固定端口 {fp}（跳过 Browser 实例发现）", DisplayName));
            stages.Add(new StageTiming { Stage = "Browser 实例发现", Duration = TimeSpan.Zero });
        }
        else
        {
            // —— 阶段 1：UDP 1434 实例发现 ——
            var discovery = await DiscoverInstanceAsync(
                target, instanceName, timeout, request.SourceAddress, ct).ConfigureAwait(false);
            stages.Add(discovery.Timing);
            if (discovery.Response is null)
            {
                run.Transport = discovery.Transport;
                run.ErrorCode = discovery.ErrorCode;
                foreach (var obs in discovery.Observations)
                    run.AddObservation(obs);
                if (discovery.Transport is TransportOutcome.Timeout)
                {
                    run.AddObservation(Observation.Now(
                        "SQL Browser (UDP 1434) 无响应——常见于固定端口部署或 Browser 服务停止。状态未确认。",
                        DisplayName));
                }
                FinishRun(run);
                return run;
            }
            foreach (var obs in discovery.Observations)
                run.AddObservation(obs);
            if (discovery.Port is null)
            {
                run.Transport = TransportOutcome.Success;
                run.Protocol = ProtocolOutcome.ServiceError;
                run.ProtocolDetail = discovery.ErrorMessage ??
                    "Browser 应答中未包含该实例的端口映射";
                run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                FinishRun(run);
                return run;
            }
            port = discovery.Port.Value;
            run.AddObservation(Observation.Now(
                $"实例发现成功：{discovery.InstanceName} → TCP {port}", DisplayName));
        }

        // —— 阶段 2：TCP 连接 ——
        var tcpRun = await new TcpConnectProbe().ExecuteAsync(
            target, port, request with
            {
                Parameters = request.Parameters with { Port = port },
            }).ConfigureAwait(false);
        stages.AddRange(tcpRun.Stages);
        run.Transport = tcpRun.Transport;
        run.ErrorCode = tcpRun.ErrorCode;
        foreach (var obs in tcpRun.Observations)
            run.AddObservation(obs with { Source = DisplayName });

        if (tcpRun.Transport is not TransportOutcome.Success)
        {
            run.Stages = stages;
            FinishRun(run);
            return run;
        }

        // —— 阶段 3：可选登录（TDS 预登录 + 认证）——
        if (tryLogin)
        {
            NoteSourceNotBindable(run, request, DisplayName, "SQL 登录阶段（SqlClient）", "驱动不支持");
            var loginSw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var builder = new SqlConnectionStringBuilder
                {
                    DataSource = $"{target}:{port}",
                    ConnectTimeout = Math.Max(1, (int)timeout.TotalSeconds),
                    Encrypt = SqlConnectionEncryptOption.Mandatory,
                };
                if (sqlCredential is not null)
                {
                    builder.UserID = sqlCredential.UserName;
                    builder.Password = sqlCredential.Password;
                }
                else
                {
                    builder.IntegratedSecurity = true;
                }

                // 凭据不进日志：连接串在异常中可能被带出，改为明确脱敏处理
                using var conn = new SqlConnection(builder.ConnectionString);
                await conn.OpenAsync(ct).ConfigureAwait(false);
                loginSw.Stop();

                run.Protocol = ProtocolOutcome.Success;
                run.ProtocolDetail = $"TCP {port} 连接成功，SQL 登录成功" +
                    (sqlCredential is null ? "（Windows 集成身份）" : "（SQL 认证）");
                run.AddObservation(Observation.Now(
                    $"SQL 登录成功（{(int)loginSw.Elapsed.TotalMilliseconds} ms，TLS 由驱动协商）",
                    DisplayName));
            }
            catch (SqlException ex) when (ex.Class >= 11 && ex.Number == -1)
            {
                run.Protocol = ProtocolOutcome.NoResponse;
                run.ProtocolDetail = $"登录超时/预协商失败：{ex.Message}";
                run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
            }
            catch (SqlException ex)
            {
                run.Protocol = ProtocolOutcome.ServiceError;
                run.ProtocolDetail =
                    $"TCP {port} 可达但 SQL 登录失败（错误号 {ex.Number}）。" +
                    "这是数据库服务的明确响应，非网络断开。" +
                    (ex.Number is 18456 ? "（Login failed——凭据或权限问题）" : "");
                run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
            }
            catch (Exception ex)
            {
                run.Protocol = ProtocolOutcome.ProtocolError;
                run.ProtocolDetail = $"登录阶段异常：{ex.Message}";
                run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
            }
        }
        else
        {
            run.Protocol = ProtocolOutcome.NotExecuted;
            run.ProtocolDetail = "TCP 可连接；按配置未尝试 SQL 登录。端口可连接不代表实例可用。";
            run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
        }

        run.Stages = stages;
        FinishRun(run);
        return run;
    }

    private sealed record DiscoveryAttempt
    {
        public StageTiming Timing { get; init; } = new() { Stage = "Browser 实例发现" };
        public TransportOutcome Transport { get; init; }
        public string? ErrorCode { get; init; }
        public IReadOnlyList<Observation> Observations { get; init; } = [];
        public string? InstanceName { get; init; }
        public int? Port { get; init; }
        public string? ErrorMessage { get; init; }
        public byte[]? Response { get; init; }
    }

    /// <summary>SSRP 协议：发 0x02，响应为 name;instance;port;... 以 ";;" 分隔的多个实例。</summary>
    private async Task<DiscoveryAttempt> DiscoverInstanceAsync(
        IPAddress target, string? instanceName, TimeSpan timeout,
        IPAddress? source, CancellationToken ct)
    {
        var observations = new List<Observation>();
        var startUtc = DateTimeOffset.UtcNow;
        using var udp = new UdpClient(target.AddressFamily);
        if (source is not null)
            udp.Client.Bind(new IPEndPoint(source, 0));

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            byte[] ssrpRequest = [0x02];
            await udp.SendAsync(ssrpRequest, new IPEndPoint(target, 1434), timeoutCts.Token)
                .ConfigureAwait(false);
            observations.Add(Observation.Now(
                "向 UDP 1434 发送 SQL Browser 实例发现请求（SSRP 0x02）", DisplayName));

            bool resetRetried = false;
            while (true)
            {
                UdpReceiveResult resp;
                try
                {
                    resp = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                }
                catch (SocketException ex) when (
                    ex.SocketErrorCode is SocketError.ConnectionReset && !resetRetried)
                {
                    resetRetried = true;
                    observations.Add(Observation.Now(
                        "收到 ICMP 不可达反馈（Browser 服务未监听 1434 或被明确拒绝）", DisplayName));
                    continue;
                }

                sw.Stop();
                var text = Encoding.ASCII.GetString(resp.Buffer);
                var (name, port, available) = ParseSsrp(text, instanceName);
                foreach (var inst in available)
                    observations.Add(Observation.Now($"Browser 通告实例：{inst}", DisplayName));

                if (name is not null)
                {
                    return new DiscoveryAttempt
                    {
                        Transport = TransportOutcome.Success,
                        Timing = new StageTiming
                        {
                            Stage = "Browser 实例发现",
                            Duration = sw.Elapsed,
                            StartUtc = startUtc,
                        },
                        InstanceName = name,
                        Port = port,
                        Observations = observations,
                        Response = resp.Buffer,
                    };
                }

                return new DiscoveryAttempt
                {
                    Transport = TransportOutcome.Success,
                    Timing = new StageTiming
                    {
                        Stage = "Browser 实例发现",
                        Duration = sw.Elapsed,
                        StartUtc = startUtc,
                    },
                    Observations = observations,
                    ErrorMessage = instanceName is null
                        ? $"Browser 应答中未解析出可用实例（原始响应 {resp.Buffer.Length} 字节）"
                        : $"Browser 应答中未找到实例 {instanceName}（可用实例见观察记录）",
                };
            }
        }
        catch (SocketException ex)
        {
            return new DiscoveryAttempt
            {
                Transport = ClassifySocketError(ex.SocketErrorCode),
                ErrorCode = ex.SocketErrorCode.ToString(),
                Observations = observations,
            };
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new DiscoveryAttempt
            {
                Transport = TransportOutcome.Timeout,
                ErrorCode = "BROWSER_TIMEOUT",
                Observations = observations,
            };
        }
    }

    /// <summary>解析 SSRP 响应。返回（匹配实例名, 端口, 通告的实例名列表）。</summary>
    public static (string? Name, int? Port, IReadOnlyList<string> Available) ParseSsrp(
        string text, string? wanted)
    {
        var available = new List<string>();
        foreach (var chunk in text.Split(";;", StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = chunk.Split(';');
            // serverName;instanceName;isClustered;version;tcpPort;np;...
            if (parts.Length < 5) continue;
            var inst = parts[1];
            available.Add(inst);
            if (wanted is null ||
                string.Equals(inst, wanted, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(parts[0], wanted, StringComparison.OrdinalIgnoreCase))
            {
                if (int.TryParse(parts[4], out var port) && port > 0)
                    return (inst, port, available);
            }
        }
        return (null, null, available);
    }
}
