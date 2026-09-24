namespace NetFlow.Domain;

/// <summary>状态判定结果。</summary>
public sealed record ConclusionVerdict
{
    public required ConclusionLevel Level { get; init; }

    /// <summary>判定说明：区分"观察事实"与"可支持的推断"，不可混写。</summary>
    public required string Rationale { get; init; }

    /// <summary>本机观察范围声明（视角限制）。</summary>
    public IReadOnlyList<string> Limitations { get; init; } = [];
}

/// <summary>
/// 统一状态判定矩阵（设计文档 5.2）。
/// 输入传输/协议观察，输出对外状态。纯函数、可单元验证、带规则版本。
/// </summary>
public static class ConclusionEvaluator
{
    /// <summary>规则版本。与 Finding.RuleVersion 和报告绑定。</summary>
    public const string RuleVersion = "rules/2026-09-23-v1.0";

    public static ConclusionVerdict Evaluate(
        TransportOutcome transport, ProtocolOutcome protocol) =>
        (transport, protocol) switch
        {
            // TCP 三次握手完成，协议未执行：端口连接成功，协议待检查
            (TransportOutcome.Success, ProtocolOutcome.NotExecuted) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Pass,
                Rationale = "TCP 连接成功（传输层）。端口可连接仅证明传输层建立，服务可用性待协议级检查。",
                Limitations = ["仅本机视角", "未执行协议级验证"],
            },

            // TCP 完成 + 协议成功
            (TransportOutcome.Success, ProtocolOutcome.Success) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Pass,
                Rationale = "传输层建立且协议交互符合所选预期。",
                Limitations = ["仅本机视角"],
            },

            // 传输成功但协议报错（如 HTTP 503、LDAP 拒绝绑定）：网络通，服务层问题
            (TransportOutcome.Success, ProtocolOutcome.ServiceError) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Warning,
                Rationale = "网络传输可达，服务返回了明确的业务层错误响应（收到有效响应，非网络断开）。",
                Limitations = ["仅本机视角", "服务层错误按所选预期规则判定"],
            },

            // 传输成功但协议不符合预期
            (TransportOutcome.Success, ProtocolOutcome.ProtocolError) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Fail,
                Rationale = "网络传输可达，但对端响应不符合协议预期。",
                Limitations = ["仅本机视角"],
            },

            // 传输成功但协议无响应（UDP 场景为主）
            (TransportOutcome.Success, ProtocolOutcome.NoResponse) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Unconfirmed,
                Rationale = "请求已发出、传输层可交互，但协议时限内未收到应答。服务状态未确认。",
                Limitations = ["仅本机视角", "未收到应答不能区分服务未监听、响应被过滤或丢包"],
            },

            // 明确拒绝
            (TransportOutcome.Refused, _) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Fail,
                Rationale = "目标明确拒绝连接（收到拒绝反馈）。这是本机观察到的明确网络事实。",
                Limitations = ["仅本机视角", "拒绝可能来自目标主机或路径上的过滤设备，本观察不能区分二者"],
            },

            // 超时：未确认，严禁归因防火墙
            (TransportOutcome.Timeout, _) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Unconfirmed,
                Rationale = "请求已发出且在时限内未收到任何反馈（未收到 RST、未收到应答）。原因未确认。",
                Limitations = [
                    "仅本机视角",
                    "无响应不能判定端口关闭，也不能判定被防火墙丢包——两种情况在本机观察上不可区分",
                ],
            },

            (TransportOutcome.Unreachable, _) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Fail,
                Rationale = "收到网络层不可达反馈。",
                Limitations = ["仅本机视角"],
            },

            (TransportOutcome.NameResolutionFailed, _) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Fail,
                Rationale = "目标名称解析失败，未发起网络连接。",
                Limitations = ["取决于本机 DNS 配置"],
            },

            (TransportOutcome.LocalError, _) => new ConclusionVerdict
            {
                Level = ConclusionLevel.Fail,
                Rationale = "本机套接字/绑定错误，探针未能发起网络操作。",
                Limitations = ["属于本机环境问题，非目标侧观察"],
            },

            _ => new ConclusionVerdict
            {
                Level = ConclusionLevel.NotChecked,
                Rationale = "未执行或观察不完整。",
                Limitations = ["无网络观察"],
            },
        };

    /// <summary>权限受限场景专用：网络可能可达但服务查询未执行 —— 未检查，不判服务停止。</summary>
    public static ConclusionVerdict NotChecked(string reason) => new()
    {
        Level = ConclusionLevel.NotChecked,
        Rationale = $"未检查：{reason}",
        Limitations = ["缺少该检查视角的授权或能力，状态未知"],
    };
}
