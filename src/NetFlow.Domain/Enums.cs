namespace NetFlow.Domain;

/// <summary>探针类别。与设计文档 4.4 协议探针表对应。</summary>
public enum ProbeType
{
    Dns,
    TcpConnect,
    UdpDatagram,
    IcmpPing,
    TraceRoute,
    Ntp,
    Http,
    Tls,
    Smtp,
    Ldap,
    SqlServer,
    Smb,
    Rdp,
    WinRm,
    Ssh,
    LocalSystemSnapshot,
    RemoteServiceQuery,
    PacketCapture,
}

/// <summary>探针执行状态（运行生命周期，与任务状态机分离）。</summary>
public enum ProbeState
{
    NotRun,
    Running,
    Completed,
    Canceled,
    Failed,
}

/// <summary>传输层观察结果。只描述本机可观察的事实，不做归因。</summary>
public enum TransportOutcome
{
    /// <summary>尚未执行。</summary>
    NotExecuted,

    /// <summary>TCP 三次握手完成 / UDP 收到匹配应答 / ICMP 回显应答。</summary>
    Success,

    /// <summary>收到明确拒绝（TCP RST、ICMP 端口不可达等明确反馈）。</summary>
    Refused,

    /// <summary>请求已发出但在时限内无任何反馈。</summary>
    Timeout,

    /// <summary>收到网络层不可达类 ICMP 错误（host/network unreachable 等）。</summary>
    Unreachable,

    /// <summary>目标名称解析失败。</summary>
    NameResolutionFailed,

    /// <summary>本机套接字/绑定/网卡等本地错误，未触及网络。</summary>
    LocalError,
}

/// <summary>协议层观察结果。仅在传输层成功后才有意义。</summary>
public enum ProtocolOutcome
{
    /// <summary>未执行协议级验证（例如仅做了端口连接）。</summary>
    NotExecuted,

    /// <summary>未支持/未实现该协议阶段。不得用传输结果冒充。</summary>
    NotSupported,

    /// <summary>按所选预期，协议交互成功。</summary>
    Success,

    /// <summary>对端返回了违反协议预期的响应（横幅异常、拒绝绑定等）。</summary>
    ProtocolError,

    /// <summary>服务层明确报错（DNS NXDOMAIN、HTTP 5xx、LDAP invalidCredentials 等）。
    /// 注意：这仍是"收到有效响应"，与网络故障性质不同。</summary>
    ServiceError,

    /// <summary>传输层成功但协议时限内无响应（例如 UDP 请求发出无应答）。</summary>
    NoResponse,
}

/// <summary>统一状态词（设计文档 3.1）。传输成功与业务通过分别判断。</summary>
public enum ConclusionLevel
{
    /// <summary>观察事实满足全部所选成功准则。</summary>
    Pass,

    /// <summary>可用但存在需要注意的观察（延迟高、证书余量不足、结果不一致等）。</summary>
    Warning,

    /// <summary>明确的失败事实（拒绝、协议错误、验证不通过）。</summary>
    Fail,

    /// <summary>请求发出但无反馈，原因无法确认。严禁输出"端口关闭/被防火墙阻断"。</summary>
    Unconfirmed,

    /// <summary>因权限/能力/条件不满足未执行。必须记录原因。</summary>
    NotChecked,

    /// <summary>按模板条件或用户操作跳过。</summary>
    Skipped,

    /// <summary>用户或系统取消。</summary>
    Canceled,
}

/// <summary>证据的观察视角（设计文档 5.3：一端观察只描述该端）。</summary>
public enum SourceSide
{
    /// <summary>本机视角（默认）。</summary>
    Local,

    /// <summary>远端目标视角（仅当导入了该端的抓包/日志）。</summary>
    Remote,

    /// <summary>第三方观察（导入文件、用户提供材料）。</summary>
    Imported,
}

/// <summary>发现严重级别。</summary>
public enum Severity
{
    Info,
    Warning,
    Error,
    Critical,
}

/// <summary>证据种类。</summary>
public enum EvidenceKind
{
    ProbeRawOutput,
    DnsWireMessage,
    TlsCertificate,
    HttpResponse,
    PacketCaptureFile,
    CaptureSummary,
    SystemStateSnapshot,
    EventLogEntries,
    ExternalToolOutput,
    ImportedFile,
}

/// <summary>脱敏级别（设计文档 8.3：脱敏报告与原始抓包是不同产物）。</summary>
public enum RedactionLevel
{
    /// <summary>原始内容，未脱敏（仅限本机原始证据文件引用）。</summary>
    Raw,

    /// <summary>按规则脱敏（令牌、凭据、可配置内网 IP 等）。</summary>
    Redacted,
}

/// <summary>证据文件留存策略。</summary>
public enum RetentionPolicy
{
    /// <summary>跟随默认留存期（可被自动清理）。</summary>
    Default,

    /// <summary>用户标记保留，不自动删除。</summary>
    Keep,

    /// <summary>会话结束即清理。</summary>
    Ephemeral,
}
