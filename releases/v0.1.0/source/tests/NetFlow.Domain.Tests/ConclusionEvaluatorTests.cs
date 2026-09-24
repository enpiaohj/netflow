using NetFlow.Domain;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>
/// 状态判定矩阵验收（对应设计文档第 12 节验收用例）。
/// 核心红线：UDP 无响应绝不输出"关闭/被防火墙阻断"。
/// </summary>
public class ConclusionEvaluatorTests
{
    [Fact]
    public void TcpSuccess_ProtocolNotExecuted_IsPassWithProtocolPending()
    {
        var v = ConclusionEvaluator.Evaluate(TransportOutcome.Success, ProtocolOutcome.NotExecuted);

        Assert.Equal(ConclusionLevel.Pass, v.Level);
        Assert.Contains("传输层", v.Rationale);
        Assert.Contains("待", v.Rationale); // 协议待检查
    }

    [Fact]
    public void TcpRefused_IsFail_AndStatesLocalObservation()
    {
        var v = ConclusionEvaluator.Evaluate(TransportOutcome.Refused, ProtocolOutcome.NotExecuted);

        Assert.Equal(ConclusionLevel.Fail, v.Level);
        Assert.Contains("明确", v.Rationale);
    }

    [Fact]
    public void TcpTimeout_IsUnconfirmed_NeverFirewallAttribution()
    {
        var v = ConclusionEvaluator.Evaluate(TransportOutcome.Timeout, ProtocolOutcome.NotExecuted);

        Assert.Equal(ConclusionLevel.Unconfirmed, v.Level);
        // 红线：不得出现"关闭"或直接归因防火墙的表述
        Assert.DoesNotContain("关闭", v.Rationale);
        Assert.DoesNotContain("被防火墙", v.Rationale);
        Assert.All(v.Limitations, l => Assert.DoesNotContain("确定丢包", l));
    }

    [Fact]
    public void UdpNoResponse_IsUnconfirmed()
    {
        // UDP 请求发出无应答：传输 Success（可交互），协议 NoResponse
        var v = ConclusionEvaluator.Evaluate(TransportOutcome.Success, ProtocolOutcome.NoResponse);

        Assert.Equal(ConclusionLevel.Unconfirmed, v.Level);
        Assert.DoesNotContain("关闭", v.Rationale);
    }

    [Fact]
    public void ServiceError_AfterTransportSuccess_IsWarningNotNetworkFailure()
    {
        // HTTP 503 / LDAP 拒绝：网络可达，服务层错误
        var v = ConclusionEvaluator.Evaluate(TransportOutcome.Success, ProtocolOutcome.ServiceError);

        Assert.Equal(ConclusionLevel.Warning, v.Level);
        Assert.Contains("有效响应", v.Rationale);
    }

    [Fact]
    public void ProtocolError_IsFail()
    {
        var v = ConclusionEvaluator.Evaluate(TransportOutcome.Success, ProtocolOutcome.ProtocolError);

        Assert.Equal(ConclusionLevel.Fail, v.Level);
    }

    [Fact]
    public void Unreachable_IsFail()
    {
        var v = ConclusionEvaluator.Evaluate(TransportOutcome.Unreachable, ProtocolOutcome.NotExecuted);

        Assert.Equal(ConclusionLevel.Fail, v.Level);
    }

    [Fact]
    public void NameResolutionFailed_IsFail()
    {
        var v = ConclusionEvaluator.Evaluate(
            TransportOutcome.NameResolutionFailed, ProtocolOutcome.NotExecuted);

        Assert.Equal(ConclusionLevel.Fail, v.Level);
        Assert.Contains("解析", v.Rationale);
    }

    [Fact]
    public void PermissionMissing_ProducesNotChecked_NotServiceStopped()
    {
        var v = ConclusionEvaluator.NotChecked("无远端服务查询权限");

        Assert.Equal(ConclusionLevel.NotChecked, v.Level);
        Assert.Contains("未检查", v.Rationale);
        Assert.DoesNotContain("停止", v.Rationale);
    }

    [Fact]
    public void RuleVersion_IsStable()
    {
        Assert.False(string.IsNullOrWhiteSpace(ConclusionEvaluator.RuleVersion));
    }
}
