using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Controls;
using NetFlow.Domain;
using NetFlow.Persistence;

namespace NetFlow.Desktop.Services;

/// <summary>
/// 界面偏好持久化：上次选择的源网卡、各输入框的最近输入，存入 SQLite（app_settings / recent_inputs）。
/// 内存缓存 + 异步写穿：界面调用是同步的，数据库写入在后台完成；数据库不可用时只保留本次运行内的记录。
/// 只保存主机名/IP/域名等非敏感输入。旧版 ui-state.json 会在首次启动时一次性导入。
/// </summary>
public static class UiState
{
    private const int MaxRecent = 15;
    private const string SourceKey = "ui.source-adapter";

    private static readonly object Gate = new();
    private static readonly string LegacyFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetFlow", "ui-state.json");

    private static Dictionary<string, ObservableCollection<string>>? _recent;
    private static string? _sourceAdapterName;

    private static DiagnosisRepository? Repository =>
        AppServices.Instance is { PersistenceReady: true, Repository: { } repo } ? repo : null;

    private sealed class LegacyState
    {
        public string? SourceAdapter { get; set; }

        public Dictionary<string, List<string>> Recent { get; set; } = [];
    }

    /// <summary>上次选择的源网卡名（下次启动时优先恢复）。</summary>
    public static string? SourceAdapterName
    {
        get
        {
            EnsureLoaded();
            return _sourceAdapterName;
        }
        set
        {
            EnsureLoaded();
            if (_sourceAdapterName == value) return;
            _sourceAdapterName = value;
            Persist(repo => repo.SetSettingAsync(SourceKey, value ?? ""), "源网卡选择");
        }
    }

    /// <summary>读取界面偏好（如上次选择的端口包）。未保存返回 null。</summary>
    public static string? GetPreference(string key)
    {
        var repo = Repository;
        if (repo is null) return _memoryPreferences.GetValueOrDefault(key);
        try
        {
            var value = repo.GetSettingAsync("pref." + key).GetAwaiter().GetResult();
            return string.IsNullOrEmpty(value) ? null : value;
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            AppLog.Warn($"界面偏好读取失败（已忽略）：{ex.Message}");
            return _memoryPreferences.GetValueOrDefault(key);
        }
    }

    public static void SetPreference(string key, string? value)
    {
        _memoryPreferences[key] = value ?? "";
        Persist(repo => repo.SetSettingAsync("pref." + key, value ?? ""), "界面偏好");
    }

    private static readonly Dictionary<string, string> _memoryPreferences = [];

    /// <summary>取某类输入的最近记录（最新在前）。同一 key 的所有输入框共享同一份列表。</summary>
    public static ObservableCollection<string> Recent(string key)
    {
        EnsureLoaded();
        lock (Gate)
        {
            if (!_recent!.TryGetValue(key, out var list))
                _recent[key] = list = [];
            return list;
        }
    }

    /// <summary>把下拉框的最近记录绑定到 key 对应的列表。</summary>
    public static void Bind(ComboBox combo, string key) => combo.ItemsSource = Recent(key);

    /// <summary>记住下拉框当前文本（去重、置顶、限长），并保持输入框文本不变。</summary>
    public static void Remember(ComboBox combo, string key)
    {
        var text = combo.Text?.Trim();
        if (string.IsNullOrEmpty(text)) return;

        var list = Recent(key);
        var index = list.IndexOf(text);
        if (index != 0)
        {
            if (index > 0) list.Move(index, 0);
            else list.Insert(0, text);
            while (list.Count > MaxRecent) list.RemoveAt(list.Count - 1);
            var usedUtc = DateTimeOffset.UtcNow; // 调用时刻定序，避免后台写入顺序影响“最近”排序
            Persist(repo => repo.AddRecentAsync(key, text, MaxRecent, default, usedUtc), "最近输入");
        }

        // 列表变动可能让编辑框清空选中项/文本，这里恢复
        if (combo.Text != text) combo.Text = text;
    }

    /// <summary>清除全部最近输入（设置页“清除历史输入”）。</summary>
    public static void ClearRecent()
    {
        EnsureLoaded();
        lock (Gate)
        {
            foreach (var list in _recent!.Values) list.Clear();
        }
        Persist(repo => repo.ClearRecentAsync(), "清除最近输入");
    }

    private static void EnsureLoaded()
    {
        lock (Gate)
        {
            if (_recent is not null) return;
            _recent = [];
            var repo = Repository;
            if (repo is null) return;

            try
            {
                MigrateLegacyFile(repo);

                var source = repo.GetSettingAsync(SourceKey).GetAwaiter().GetResult();
                _sourceAdapterName = string.IsNullOrEmpty(source) ? null : source;

                foreach (var kind in KnownKinds)
                {
                    var values = repo.ListRecentAsync(kind, MaxRecent).GetAwaiter().GetResult();
                    _recent[kind] = new ObservableCollection<string>(values);
                }
            }
            catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
            {
                AppLog.Warn($"界面偏好读取失败（已忽略）：{ex.Message}");
            }
        }
    }

    /// <summary>各输入框使用的类别（启动时预载）。</summary>
    private static readonly string[] KnownKinds = ["target", "domain", "ip", "hostport", "server"];

    /// <summary>旧版 JSON 偏好一次性导入数据库后改名保留（.migrated），不删除用户文件。</summary>
    private static void MigrateLegacyFile(DiagnosisRepository repo)
    {
        if (!File.Exists(LegacyFile)) return;
        try
        {
            var legacy = JsonSerializer.Deserialize<LegacyState>(File.ReadAllText(LegacyFile));
            if (legacy is not null)
            {
                if (!string.IsNullOrEmpty(legacy.SourceAdapter))
                    repo.SetSettingAsync(SourceKey, legacy.SourceAdapter).GetAwaiter().GetResult();
                var baseTime = DateTimeOffset.UtcNow;
                foreach (var (kind, values) in legacy.Recent)
                {
                    // 旧列表最新在前：从最旧开始写入，保持先后顺序
                    for (var i = values.Count - 1; i >= 0; i--)
                    {
                        repo.AddRecentAsync(kind, values[i], MaxRecent, default,
                            baseTime.AddMilliseconds(-i)).GetAwaiter().GetResult();
                    }
                }
            }
            File.Move(LegacyFile, LegacyFile + ".migrated", overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException
                                       or Microsoft.Data.Sqlite.SqliteException)
        {
            AppLog.Warn($"旧版界面偏好导入失败（已忽略）：{ex.Message}");
        }
    }

    /// <summary>后台写库：失败只记日志，不打断界面。</summary>
    private static void Persist(Func<DiagnosisRepository, Task> write, string what)
    {
        var repo = Repository;
        if (repo is null) return;
        _ = Task.Run(async () =>
        {
            try
            {
                await write(repo).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                AppLog.Warn($"{what}保存失败（本次运行内仍有效）：{ex.Message}");
            }
        });
    }
}
