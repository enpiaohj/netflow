using System.Text.Json;
using NetFlow.Domain;

namespace NetFlow.Application;

/// <summary>用户场景模板文件（含版本历史）。</summary>
public sealed record UserTemplateFile
{
    public required string Id { get; init; }

    /// <summary>派生自哪个内置模板（origin）。</summary>
    public string? OriginId { get; init; }

    public required string Name { get; init; }

    public required string Description { get; init; }

    public required string Direction { get; init; }

    /// <summary>语义化版本：编辑一次递增 MINOR。</summary>
    public required string Version { get; init; }

    public required DateTimeOffset UpdatedUtc { get; init; }

    public required IReadOnlyList<ScenarioStep> Steps { get; init; }
}

/// <summary>
/// 用户模板存储（设计文档 4.7：内置模板只读，用户复制后编辑；
/// 执行时固化快照，编辑不重写历史报告）。
/// </summary>
public sealed class UserTemplateStore
{
    private readonly string _storePath;
    private readonly List<UserTemplateFile> _cache = [];
    private readonly object _lock = new();

    public UserTemplateStore(string? storePath = null)
    {
        _storePath = storePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "NetFlow", "user-templates.json");
        var dir = Path.GetDirectoryName(_storePath);
        if (dir is not null) Directory.CreateDirectory(dir);
        Load();
    }

    public IReadOnlyList<UserTemplateFile> All
    {
        get { lock (_lock) return _cache.ToArray(); }
    }

    /// <summary>从内置模板复制出用户模板（版本 1.0.0 起）。</summary>
    public UserTemplateFile CreateFromBuiltin(ScenarioTemplate source, string newName)
    {
        var item = new UserTemplateFile
        {
            Id = $"user.{Guid.NewGuid():N}",
            OriginId = source.Id,
            Name = newName,
            Description = $"复制自 {source.Name}（{source.Description}）",
            Direction = source.Direction,
            Version = "1.0.0",
            UpdatedUtc = DateTimeOffset.UtcNow,
            Steps = source.Steps,
        };
        lock (_lock) _cache.Add(item);
        Save();
        return item;
    }

    /// <summary>更新步骤（版本递增 MINOR，保留修改历史于 UpdatedUtc）。</summary>
    public UserTemplateFile UpdateSteps(string id, IReadOnlyList<ScenarioStep> steps)
    {
        lock (_lock)
        {
            var idx = _cache.FindIndex(t => t.Id == id);
            if (idx < 0) throw new KeyNotFoundException($"用户模板不存在：{id}");
            var old = _cache[idx];
            var version = BumpMinor(old.Version);
            _cache[idx] = old with
            {
                Steps = steps,
                Version = version,
                UpdatedUtc = DateTimeOffset.UtcNow,
            };
            Save();
            return _cache[idx];
        }
    }

    public bool Delete(string id)
    {
        bool removed;
        lock (_lock) removed = _cache.RemoveAll(t => t.Id == id) > 0;
        if (removed) Save();
        return removed;
    }

    /// <summary>转成执行用模板（固定 origin 版本进入快照）。</summary>
    public ScenarioTemplate ToTemplate(UserTemplateFile file) => new()
    {
        Id = file.Id,
        Name = file.Name,
        Description = file.Description,
        Direction = file.Direction,
        Version = file.Version,
        RequiredPermission = "与来源模板一致；编辑版本 " + file.Version,
        Steps = file.Steps,
    };

    private static string BumpMinor(string version)
    {
        var parts = version.Split('.');
        if (parts.Length == 3 && int.TryParse(parts[1], out var minor) && int.TryParse(parts[2], out _))
            return $"{parts[0]}.{minor + 1}.0";
        return version + ".1";
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_storePath)) return;
            var list = JsonSerializer.Deserialize<List<UserTemplateFile>>(
                File.ReadAllText(_storePath), JsonOpts);
            if (list is not null)
                lock (_lock) _cache.AddRange(list);
        }
        catch (JsonException ex)
        {
            // 存储损坏：保留现场备份后以空列表启动，绝不静默覆盖用户数据
            var backup = _storePath + $".corrupt-{DateTime.Now:yyyyMMdd-HHmmss}.bak";
            try
            {
                File.Copy(_storePath, backup, overwrite: true);
                BrokenBackupPath = backup;
            }
            catch (IOException)
            {
                BrokenBackupPath = null;
            }
            BrokenReason = $"用户模板文件损坏（{ex.Message}）。" +
                (BrokenBackupPath is { } b ? $"原文件已备份到 {b}。" : "备份失败，原文件保持原样未删除。") +
                "本次以空模板列表启动。";
        }
        catch (IOException)
        {
            // 文件被占用等暂时性问题：以空列表启动，保留原文件，不标损坏
        }
    }

    /// <summary>加载失败时的现场说明（UI 应展示；null = 正常）。</summary>
    public string? BrokenReason { get; private set; }

    public string? BrokenBackupPath { get; private set; }

    private void Save()
    {
        List<UserTemplateFile> snapshot;
        lock (_lock) snapshot = [.. _cache];
        var tmp = _storePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(snapshot, JsonOpts));
        File.Move(tmp, _storePath, overwrite: true);
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
    };
}
