using NetFlow.Application;
using NetFlow.Domain;
using Xunit;

namespace NetFlow.Domain.Tests;

public class UserTemplateStoreTests : IDisposable
{
    private readonly string _path;

    public UserTemplateStoreTests()
    {
        _path = Path.Combine(Path.GetTempPath(), $"netflow-templates-{Guid.NewGuid():N}.json");
    }

    [Fact]
    public void CreateFromBuiltin_KeepsOriginAndVersion()
    {
        var store = new UserTemplateStore(_path);
        var created = store.CreateFromBuiltin(BuiltinTemplates.AdClientToDc, "我的 AD 检查");

        Assert.StartsWith("user.", created.Id);
        Assert.Equal("builtin.ad-client-dc", created.OriginId);
        Assert.Equal("1.0.0", created.Version);
        Assert.Equal(BuiltinTemplates.AdClientToDc.Steps.Count, created.Steps.Count);
    }

    [Fact]
    public void UpdateSteps_BumpsMinorVersion()
    {
        var store = new UserTemplateStore(_path);
        var created = store.CreateFromBuiltin(BuiltinTemplates.WebApi, "x");
        var updated = store.UpdateSteps(created.Id,
        [
            new ScenarioStep { Name = "自定义步骤", ProbeType = ProbeType.TcpConnect },
        ]);

        Assert.Equal("1.1.0", updated.Version);
        Assert.Single(updated.Steps);
    }

    [Fact]
    public void PersistAcrossInstances()
    {
        var first = new UserTemplateStore(_path);
        first.CreateFromBuiltin(BuiltinTemplates.NtpCheck, "持久化检查");

        var second = new UserTemplateStore(_path);
        var item = Assert.Single(second.All);
        Assert.Equal("持久化检查", item.Name);

        var template = second.ToTemplate(item);
        Assert.Equal(item.Version, template.Version);
        Assert.Equal(item.Id, template.Id);
    }

    [Fact]
    public void Delete_Removes()
    {
        var store = new UserTemplateStore(_path);
        var created = store.CreateFromBuiltin(BuiltinTemplates.SmbShare, "待删除");
        Assert.True(store.Delete(created.Id));
        Assert.Empty(store.All);
    }

    public void Dispose()
    {
        if (File.Exists(_path)) File.Delete(_path);
    }
}
