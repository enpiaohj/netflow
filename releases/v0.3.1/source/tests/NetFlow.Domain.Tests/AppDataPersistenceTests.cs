using NetFlow.Application;
using NetFlow.Persistence;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>应用数据（设置、端口包、最近输入）的 SQLite 持久化。</summary>
public sealed class AppDataPersistenceTests : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "netflow-tests-" + Guid.NewGuid().ToString("N"));
    private string Db => Path.Combine(_dir, "test.db");

    public Task InitializeAsync()
    {
        Directory.CreateDirectory(_dir);
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* 临时目录清理失败不影响结果 */ }
        return Task.CompletedTask;
    }

    private async Task<DiagnosisRepository> OpenAsync()
    {
        var repo = new DiagnosisRepository(Db);
        await repo.InitializeAsync();
        return repo;
    }

    [Fact]
    public async Task 设置_写入后重新打开仍在_覆盖生效()
    {
        await using (var repo = await OpenAsync())
        {
            Assert.Null(await repo.GetSettingAsync("k"));
            await repo.SetSettingAsync("k", "v1");
            await repo.SetSettingAsync("k", "v2");
        }
        await using var again = await OpenAsync();
        Assert.Equal("v2", await again.GetSettingAsync("k"));
    }

    [Fact]
    public async Task 迁移可重复执行_不破坏已有数据()
    {
        await using (var repo = await OpenAsync())
            await repo.SetSettingAsync("keep", "me");
        // 连续多次打开 = 多次迁移
        for (var i = 0; i < 3; i++)
        {
            await using var repo = await OpenAsync();
            Assert.Equal("me", await repo.GetSettingAsync("keep"));
        }
    }

    [Fact]
    public async Task 端口包_增改删_名称唯一()
    {
        await using var repo = await OpenAsync();
        var now = DateTimeOffset.UtcNow;
        await repo.UpsertPortPackAsync(new PortPackRecord("a", "包A", "d", "tcp/1", now));
        await repo.UpsertPortPackAsync(new PortPackRecord("b", "包B", "", "tcp/2", now));

        // 同 Id 覆盖（含改名）
        await repo.UpsertPortPackAsync(new PortPackRecord("a", "包A2", "d2", "tcp/3", now));
        var list = await repo.ListPortPacksAsync();
        Assert.Equal(["包A2", "包B"], list.Select(p => p.Name));
        Assert.Equal("tcp/3", list.Single(p => p.Id == "a").Entries);

        // 不同 Id 使用已存在的名称 → 明确报错
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            repo.UpsertPortPackAsync(new PortPackRecord("c", "包B", "", "tcp/4", now)));
        Assert.Contains("包B", ex.Message);

        Assert.True(await repo.DeletePortPackAsync("a"));
        Assert.False(await repo.DeletePortPackAsync("a"));
        Assert.Single(await repo.ListPortPacksAsync());
    }

    [Fact]
    public async Task 最近输入_最新在前_去重刷新_按类别限长_可清除()
    {
        await using var repo = await OpenAsync();
        var t0 = DateTimeOffset.UtcNow;
        await repo.AddRecentAsync("target", "a", 3, default, t0);
        await repo.AddRecentAsync("target", "b", 3, default, t0.AddSeconds(1));
        await repo.AddRecentAsync("target", "c", 3, default, t0.AddSeconds(2));
        await repo.AddRecentAsync("ip", "1.1.1.1", 3, default, t0);

        // 再次使用 a → 置顶；超出上限时淘汰最旧的（b）
        await repo.AddRecentAsync("target", "a", 3, default, t0.AddSeconds(3));
        await repo.AddRecentAsync("target", "d", 3, default, t0.AddSeconds(4));

        Assert.Equal(["d", "a", "c"], await repo.ListRecentAsync("target"));
        Assert.Equal(["1.1.1.1"], await repo.ListRecentAsync("ip")); // 类别互不影响

        await repo.ClearRecentAsync("target");
        Assert.Empty(await repo.ListRecentAsync("target"));
        Assert.Single(await repo.ListRecentAsync("ip"));
        await repo.ClearRecentAsync();
        Assert.Empty(await repo.ListRecentAsync("ip"));
    }

    [Fact]
    public async Task 端口包存储_自定义包持久化_内置名称不可覆盖_可删除()
    {
        await using (var repo = await OpenAsync())
        {
            var store = new PortPackStore(repo);
            Assert.True(store.IsPersistent);

            var saved = await store.SaveAsync(null, "我的应用", "测试", "tcp/8080\nudp/123 NTP");
            Assert.False(saved.IsBuiltin);
            Assert.StartsWith("user.", saved.Id);

            // 覆盖已有自定义包
            await store.SaveAsync(saved.Id, "我的应用", "测试2", "tcp/9090");

            var ex1 = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.SaveAsync(null, "客户端 → AD 域控", "", "tcp/1"));
            Assert.Contains("内置", ex1.Message);

            await Assert.ThrowsAsync<InvalidOperationException>(() => store.SaveAsync(null, "", "", "tcp/1"));
            await Assert.ThrowsAsync<InvalidOperationException>(() => store.SaveAsync(null, "空包", "", "# 只有注释"));
            var ex2 = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                store.SaveAsync(null, "坏包", "", "tcp/80\n乱写"));
            Assert.Contains("第 2 行", ex2.Message);
        }

        // 重新打开：自定义包仍在，内置包不受影响
        await using var repo2 = await OpenAsync();
        var reopened = new PortPackStore(repo2);
        var user = Assert.Single(reopened.User);
        Assert.Equal("我的应用", user.Name);
        Assert.Equal("测试2", user.Description);
        Assert.Equal([new PortEntry(PortProtocol.Tcp, 9090, "")], user.Entries);
        Assert.Equal(BuiltinPortPacks.All.Count + 1, reopened.All.Count);

        Assert.False(await reopened.DeleteAsync(BuiltinPortPacks.All[0].Id)); // 内置不可删
        Assert.True(await reopened.DeleteAsync(user.Id));
        Assert.Empty(new PortPackStore(repo2).User);
    }

    [Fact]
    public async Task 端口包存储_数据库不可用时降级为内存()
    {
        var store = new PortPackStore(repository: null);
        Assert.False(store.IsPersistent);
        var saved = await store.SaveAsync(null, "临时包", "", "tcp/1234");
        Assert.Contains(store.All, p => p.Id == saved.Id);
    }

    [Fact]
    public async Task 设置存储_持久化_重开后读回_非法值被修正()
    {
        await using (var repo = await OpenAsync())
        {
            var store = new AppSettingsStore(repo);
            Assert.Equal(3, store.Current.DefaultTimeoutSeconds);
            await store.UpdateAsync(s => s with
            {
                DefaultTimeoutSeconds = 5,
                CaptureMode = "live",
                BatchConcurrency = 999, // 越界
                RedactionEnabled = false,
            });
        }
        await using var repo2 = await OpenAsync();
        var reopened = new AppSettingsStore(repo2).Current;
        Assert.Equal(5, reopened.DefaultTimeoutSeconds);
        Assert.Equal("live", reopened.CaptureMode);
        Assert.Equal(32, reopened.BatchConcurrency);
        Assert.False(reopened.RedactionEnabled);
    }

    [Fact]
    public void 设置修正_非法输入回落到安全默认值()
    {
        var s = AppSettingsStore.Normalize(new AppSettings
        {
            DefaultTimeoutSeconds = -1,
            CaptureMode = "weird",
            CaptureDurationSeconds = 1,
            CaptureSnapBytes = 99999,
            RetentionDays = 0,
            Ai = new AiSettings { BaseUrl = " ", Model = "", TimeoutSeconds = 1 },
        });

        Assert.Equal(3, s.DefaultTimeoutSeconds);
        Assert.Equal("record", s.CaptureMode);
        Assert.Equal(10, s.CaptureDurationSeconds);
        Assert.Equal(1514, s.CaptureSnapBytes);
        Assert.Equal(1, s.RetentionDays);
        Assert.Equal("https://api.deepseek.com", s.Ai.BaseUrl);
        Assert.Equal("deepseek-flash", s.Ai.Model);
        Assert.Equal(10, s.Ai.TimeoutSeconds);
        Assert.Equal("low", s.Ai.ReasoningEffort);

        Assert.Equal("high", AppSettingsStore.Normalize(new AppSettings { Ai = new AiSettings { ReasoningEffort = " HIGH " } }).Ai.ReasoningEffort);
        Assert.Equal("", AppSettingsStore.Normalize(new AppSettings { Ai = new AiSettings { ReasoningEffort = "" } }).Ai.ReasoningEffort);
        Assert.Equal("low", AppSettingsStore.Normalize(new AppSettings { Ai = new AiSettings { ReasoningEffort = "turbo" } }).Ai.ReasoningEffort);
    }

    [Fact]
    public async Task ApiKey_只以密文入库_可读回_可清除()
    {
        const string secret = "sk-test-1234567890abcdef";
        await using var repo = await OpenAsync();
        var store = new AppSettingsStore(repo);

        Assert.False(store.HasApiKey);
        await store.SetApiKeyAsync(secret);
        Assert.True(store.HasApiKey);
        Assert.Equal(secret, store.TryGetApiKey());
        Assert.Equal("sk-••••••cdef", store.MaskedApiKey());

        // 数据库中不得出现明文
        var json = await repo.GetSettingAsync("app.settings");
        Assert.NotNull(json);
        Assert.DoesNotContain(secret, json);
        Assert.DoesNotContain("1234567890", json);

        await store.SetApiKeyAsync("   ");
        Assert.False(store.HasApiKey);
        Assert.Null(store.TryGetApiKey());
        Assert.Equal("", store.MaskedApiKey());
    }
}
