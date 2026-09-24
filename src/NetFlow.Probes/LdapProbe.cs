using System.DirectoryServices.Protocols;
using System.Net;
using NetFlow.Domain;

namespace NetFlow.Probes;

/// <summary>LDAP 绑定身份模式。</summary>
public enum LdapBindMode
{
    /// <summary>匿名绑定。</summary>
    Anonymous,

    /// <summary>当前 Windows 身份（默认）。</summary>
    CurrentIdentity,

    /// <summary>显式提供凭据（DPAPI 保护的秘密在应用层解出后传入）。</summary>
    Explicit,
}

/// <summary>
/// LDAP/LDAPS 探针（设计文档 4.4）：匿名/当前身份/提供凭据的 Bind、RootDSE 查询。
/// TCP 389 成功不代表 LDAP 身份验证成功 —— Bind 结果单独呈现。
/// </summary>
public sealed class LdapProbe : ProbeBase
{
    public override ProbeType Type => ProbeType.Ldap;

    public override string DisplayName => "LDAP/LDAPS";

    public async Task<ProbeRun> ExecuteAsync(
        string host, int port, bool useSsl, LdapBindMode bindMode,
        NetworkCredential? explicitCredential, ProbeRequest request)
    {
        var run = NewRun(request);
        var ct = request.CancellationToken;
        run.AddObservation(Observation.Now(
            $"LDAP 探测：{host}:{port}{(useSsl ? "（LDAPS）" : "")}，绑定模式 {bindMode}", DisplayName));

        NoteSourceNotBindable(run, request, DisplayName, "LDAP 绑定与查询",
            "System.DirectoryServices.Protocols 不支持");

        if (useSsl)
        {
            // LDAPS 走 TLS，先做传输层确认（证书校验结果单独呈现）
            run.AddObservation(Observation.Now(
                "LDAPS 的证书验证细节建议配合 TLS 探针；本探针记录 Bind 与目录查询结果", DisplayName));
        }

        return await Task.Run(() =>
        {
            LdapConnection? conn = null;
            try
            {
                conn = new LdapConnection(new LdapDirectoryIdentifier(host, port, false, false))
                {
                    AuthType = bindMode == LdapBindMode.Anonymous
                        ? AuthType.Anonymous
                        : AuthType.Negotiate,
                };
                conn.SessionOptions.SecureSocketLayer = useSsl;
                conn.Timeout = request.Parameters.Timeout;

                var connectSw = System.Diagnostics.Stopwatch.StartNew();
                try
                {
                    if (bindMode == LdapBindMode.Anonymous)
                    {
                        conn.Bind(new NetworkCredential("", "", ""));
                    }
                    else if (bindMode == LdapBindMode.Explicit && explicitCredential is not null)
                    {
                        conn.AuthType = AuthType.Negotiate;
                        conn.Bind(explicitCredential);
                    }
                    else
                    {
                        conn.Bind(); // 当前进程身份
                    }
                    connectSw.Stop();
                }
                catch (LdapException bindEx) when (
                    bindEx.ErrorCode == 49 ||
                    string.Equals(bindEx.ServerErrorMessage?.Trim(),
                        "data 525", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(bindEx.ServerErrorMessage?.Trim(),
                        "data 52e", StringComparison.OrdinalIgnoreCase))
                {
                    // 49 = invalidCredentials（或带 data xxx 子码）
                    run.Transport = TransportOutcome.Success;
                    run.Protocol = ProtocolOutcome.ServiceError;
                    run.ProtocolDetail =
                        $"TCP 可达但 LDAP Bind 被拒绝（invalidCredentials，服务器错误码 49）。" +
                        "这证明目录服务在响应，是身份验证问题，不是网络问题。";
                    run.AddObservation(Observation.Now(run.ProtocolDetail, DisplayName));
                    FinishRun(run);
                    return run;
                }

                run.Transport = TransportOutcome.Success;
                run.Stages = [new StageTiming
                {
                    Stage = "LDAP 连接 + Bind",
                    Duration = connectSw.Elapsed,
                    StartUtc = run.StartUtc,
                }];
                run.AddObservation(Observation.Now(
                    $"LDAP Bind 成功（{(int)connectSw.Elapsed.TotalMilliseconds} ms，AuthType={conn.AuthType}）",
                    DisplayName));

                // RootDSE 查询
                var searchSw = System.Diagnostics.Stopwatch.StartNew();
                var request_ = new SearchRequest(
                    "", "(objectClass=*)", SearchScope.Base,
                    "defaultNamingContext", "namingContexts", "supportedLDAPVersion",
                    "dnsHostName");
                var response = (SearchResponse)conn.SendRequest(request_);
                searchSw.Stop();

                foreach (SearchResultEntry entry in response.Entries)
                {
                    foreach (string attr in entry.Attributes.AttributeNames)
                    {
                        var values = entry.Attributes[attr]
                            .GetValues(typeof(string)).Cast<string>();
                        run.AddObservation(Observation.Now(
                            $"RootDSE {attr} = {string.Join("; ", values)}", DisplayName));
                    }
                }

                run.Protocol = ProtocolOutcome.Success;
                run.ProtocolDetail = $"Bind 成功，RootDSE 查询成功（{(int)searchSw.Elapsed.TotalMilliseconds} ms）";
                FinishRun(run);
                return run;
            }
            catch (LdapException ex)
            {
                // 连接层失败：0x51 ServerDown（端口拒绝/不可达）、0x55 超时等
                run.Transport = ex.ErrorCode switch
                {
                    0x51 => TransportOutcome.Refused,
                    -1 => TransportOutcome.Timeout,
                    _ => TransportOutcome.LocalError,
                };
                run.ErrorCode = $"LDAP_0x{ex.ErrorCode:X}";
                run.AddObservation(Observation.Now(
                    $"LDAP 错误 0x{ex.ErrorCode:X}：{ex.Message}", DisplayName));
                FinishRun(run);
                return run;
            }
            catch (Exception ex) when (ex is not LdapException)
            {
                run.Transport = TransportOutcome.LocalError;
                run.ErrorCode = ex.GetType().Name;
                run.AddObservation(Observation.Now($"本地错误：{ex.Message}", DisplayName));
                FinishRun(run, ProbeState.Failed);
                return run;
            }
            finally
            {
                conn?.Dispose();
            }
        }, ct);
    }
}
