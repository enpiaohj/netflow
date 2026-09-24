using NetFlow.Domain;
using NetFlow.Persistence;

namespace NetFlow.Application;

/// <summary>
/// 端口包存储：内置端口包只读，自定义端口包持久化到 SQLite（port_packs 表）。
/// 数据库不可用时自定义端口包仅在本次运行内有效（<see cref="IsPersistent"/> 为 false）。
/// </summary>
public sealed class PortPackStore
{
    public const int MaxNameLength = 40;

    private readonly DiagnosisRepository? _repository;
    private readonly List<PortPack> _user = [];
    private readonly object _lock = new();

    public PortPackStore(DiagnosisRepository? repository)
    {
        _repository = repository;
        Load();
    }

    public bool IsPersistent => _repository is not null;

    /// <summary>端口包列表变化（新增/覆盖/删除）。</summary>
    public event EventHandler? Changed;

    public IReadOnlyList<PortPack> User
    {
        get { lock (_lock) return [.. _user]; }
    }

    /// <summary>内置 + 自定义（自定义按名称排序在后）。</summary>
    public IReadOnlyList<PortPack> All => [.. BuiltinPortPacks.All, .. User];

    public PortPack? Find(string id) => All.FirstOrDefault(p => p.Id == id);

    private void Load()
    {
        if (_repository is null) return;
        try
        {
            var records = _repository.ListPortPacksAsync().GetAwaiter().GetResult();
            lock (_lock)
            {
                _user.Clear();
                foreach (var r in records)
                {
                    var parsed = PortPackText.Parse(r.Entries);
                    if (parsed.Entries.Count == 0) continue; // 损坏记录不展示，不影响其它
                    _user.Add(new PortPack
                    {
                        Id = r.Id, Name = r.Name, Description = r.Description, Entries = parsed.Entries,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            AppLog.Warn($"自定义端口包读取失败（已忽略）：{ex.Message}");
        }
    }

    /// <summary>
    /// 保存自定义端口包。existingId 为已有自定义包的 Id 时覆盖，否则新建。
    /// 校验失败抛 <see cref="InvalidOperationException"/>，消息可直接展示给用户。
    /// </summary>
    public async Task<PortPack> SaveAsync(
        string? existingId, string name, string description, string entriesText,
        CancellationToken ct = default)
    {
        name = name.Trim();
        if (name.Length == 0) throw new InvalidOperationException("请填写端口包名称");
        if (name.Length > MaxNameLength) throw new InvalidOperationException($"名称过长（最多 {MaxNameLength} 个字符）");
        if (BuiltinPortPacks.All.Any(b => b.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException($"“{name}”是内置端口包名称，内置端口包不可覆盖，请换一个名称另存为自定义端口包");

        var parsed = PortPackText.Parse(entriesText);
        if (parsed.Errors.Count > 0) throw new InvalidOperationException(string.Join("\n", parsed.Errors));
        if (parsed.Entries.Count == 0) throw new InvalidOperationException("端口包至少需要一个端口");

        var isExisting = existingId is not null && User.Any(p => p.Id == existingId);
        var id = isExisting ? existingId! : $"user.{Guid.NewGuid():N}";

        lock (_lock)
        {
            if (_user.Any(p => p.Id != id && p.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException($"已存在同名端口包：{name}");
        }

        var pack = new PortPack { Id = id, Name = name, Description = description.Trim(), Entries = parsed.Entries };
        if (_repository is not null)
        {
            await _repository.UpsertPortPackAsync(new PortPackRecord(
                id, name, pack.Description, PortPackText.Format(pack.Entries), DateTimeOffset.UtcNow), ct)
                .ConfigureAwait(false);
        }

        lock (_lock)
        {
            var index = _user.FindIndex(p => p.Id == id);
            if (index >= 0) _user[index] = pack; else _user.Add(pack);
            _user.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase));
        }
        Changed?.Invoke(this, EventArgs.Empty);
        return pack;
    }

    /// <summary>删除自定义端口包；内置端口包不可删除。</summary>
    public async Task<bool> DeleteAsync(string id, CancellationToken ct = default)
    {
        if (BuiltinPortPacks.All.Any(p => p.Id == id)) return false;

        bool removed;
        lock (_lock) removed = _user.RemoveAll(p => p.Id == id) > 0;
        if (removed && _repository is not null)
            await _repository.DeletePortPackAsync(id, ct).ConfigureAwait(false);
        if (removed) Changed?.Invoke(this, EventArgs.Empty);
        return removed;
    }
}
