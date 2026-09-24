using NetFlow.Domain;

namespace NetFlow.Application;

/// <summary>
/// 场景模板定义（设计文档 4.7）：角色、方向、步骤、依赖、条件、成功准则、版本。
/// 内置模板只读；用户复制后编辑；执行时固化快照。
/// </summary>
public sealed class ScenarioTemplate
{
    public required string Id { get; init; }

    public required string Name { get; init; }

    public required string Description { get; init; }

    /// <summary>方向（如 客户端→域控制器）。</summary>
    public required string Direction { get; init; }

    public required string Version { get; init; }

    /// <summary>最低权限说明。</summary>
    public required string RequiredPermission { get; init; }

    public required IReadOnlyList<ScenarioStep> Steps { get; init; }

    public ScenarioSnapshot ToSnapshot() => new()
    {
        TemplateId = Id,
        TemplateName = Name,
        TemplateVersion = Version,
        Direction = Direction,
        Steps = Steps,
    };
}
