using System.Text.Json;
using NetFlow.Domain;
using NetFlow.Persistence;
using NetFlow.Windows;

namespace NetFlow.Application;

/// <summary>AI 分析设置（当前支持 DeepSeek，接口为 OpenAI 兼容的 chat/completions）。</summary>
public sealed record AiSettings
{
    /// <summary>DeepSeek 官方现行模型（与 GET /models 一致）；旧名 deepseek-chat / deepseek-reasoner 仅为兼容别名。</summary>
    public const string DefaultModel = "deepseek-flash";

    public bool Enabled { get; init; }

    public string Provider { get; init; } = "DeepSeek";

    /// <summary>API 根地址（不含 /chat/completions）。</summary>
    public string BaseUrl { get; init; } = "https://api.deepseek.com";

    public string Model { get; init; } = DefaultModel;

    /// <summary>API Key 的 DPAPI（当前用户）密文；不存明文。</summary>
    public string? ProtectedApiKey { get; init; }

    public int TimeoutSeconds { get; init; } = 120;

    /// <summary>推理强度：low / high / max；空 = 不指定（由服务端默认）。强度越高越慢，且消耗更多输出额度。</summary>
    public string ReasoningEffort { get; init; } = "low";

    /// <summary>每次发送前展示将发送的内容并要求确认。</summary>
    public bool ConfirmBeforeSend { get; init; } = true;

    /// <summary>发送前把 IPv4 地址替换为占位符（IP-1…），返回结果在本地还原。</summary>
    public bool MaskAddresses { get; init; }
}

/// <summary>应用设置（整体以 JSON 存入 SQLite 的 app_settings 表；未知字段忽略，缺失字段取默认值）。</summary>
public sealed record AppSettings
{
    public int SchemaVersion { get; init; } = 1;

    // ---- 网络测试 ----
    public double DefaultTimeoutSeconds { get; init; } = 3;

    public int BatchConcurrency { get; init; } = 8;

    // ---- 抓包 ----
    /// <summary>record = 记录后分析（保存 PCAPNG）；live = 实时显示（不保存文件）。</summary>
    public string CaptureMode { get; init; } = "record";

    public int CaptureDurationSeconds { get; init; } = 120;

    public int CaptureSnapBytes { get; init; } = 128;

    // ---- 数据与隐私 ----
    public bool RedactionEnabled { get; init; } = true;

    public int RetentionDays { get; init; } = 30;

    // ---- AI ----
    public AiSettings Ai { get; init; } = new();
}

/// <summary>
/// 设置存储：内存缓存 + 写穿到 SQLite。数据库不可用时只保留本次运行内的修改。
/// API Key 只保存 DPAPI 密文，不写日志、不出现在错误信息里。
/// </summary>
public sealed class AppSettingsStore
{
    private const string Key = "app.settings";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
    };

    private readonly DiagnosisRepository? _repository;
    private readonly DpapiCredentialProtector _protector = new();
    private readonly object _lock = new();
    private AppSettings _current = new();

    public AppSettingsStore(DiagnosisRepository? repository)
    {
        _repository = repository;
        Load();
    }

    public AppSettings Current
    {
        get { lock (_lock) return _current; }
    }

    public bool IsPersistent => _repository is not null;

    public event EventHandler<AppSettings>? Changed;

    private void Load()
    {
        if (_repository is null) return;
        try
        {
            var json = _repository.GetSettingAsync(Key).GetAwaiter().GetResult();
            if (!string.IsNullOrWhiteSpace(json))
                _current = Normalize(JsonSerializer.Deserialize<AppSettings>(json, JsonOptions) ?? new AppSettings());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        {
            AppLog.Warn($"应用设置读取失败，使用默认值：{ex.Message}");
        }
    }

    /// <summary>修正越界/非法值（手改数据库或旧版本数据），保证下游不会拿到非法配置。</summary>
    public static AppSettings Normalize(AppSettings s) => s with
    {
        DefaultTimeoutSeconds = double.IsFinite(s.DefaultTimeoutSeconds) && s.DefaultTimeoutSeconds is > 0 and <= 60
            ? s.DefaultTimeoutSeconds : 3,
        BatchConcurrency = Math.Clamp(s.BatchConcurrency, 1, 32),
        CaptureMode = s.CaptureMode is "live" ? "live" : "record",
        CaptureDurationSeconds = Math.Clamp(s.CaptureDurationSeconds, 10, 3600),
        CaptureSnapBytes = Math.Clamp(s.CaptureSnapBytes, 0, 1514),
        RetentionDays = Math.Clamp(s.RetentionDays, 1, 3650),
        Ai = s.Ai with
        {
            Provider = string.IsNullOrWhiteSpace(s.Ai.Provider) ? "DeepSeek" : s.Ai.Provider,
            BaseUrl = string.IsNullOrWhiteSpace(s.Ai.BaseUrl) ? "https://api.deepseek.com" : s.Ai.BaseUrl.Trim(),
            Model = string.IsNullOrWhiteSpace(s.Ai.Model) ? AiSettings.DefaultModel : s.Ai.Model.Trim(),
            TimeoutSeconds = Math.Clamp(s.Ai.TimeoutSeconds, 10, 600),
            ReasoningEffort = s.Ai.ReasoningEffort?.Trim().ToLowerInvariant() is "low" or "high" or "max" or ""
                ? s.Ai.ReasoningEffort.Trim().ToLowerInvariant() : "low",
        },
    };

    /// <summary>更新设置并持久化（先更新内存，保证界面立即生效）。</summary>
    public async Task UpdateAsync(Func<AppSettings, AppSettings> change, CancellationToken ct = default)
    {
        AppSettings updated;
        lock (_lock)
        {
            updated = Normalize(change(_current));
            _current = updated;
        }
        Changed?.Invoke(this, updated);

        if (_repository is null) return;
        try
        {
            await _repository.SetSettingAsync(Key, JsonSerializer.Serialize(updated, JsonOptions), ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or InvalidOperationException)
        {
            AppLog.Warn($"应用设置保存失败（本次运行内仍有效）：{ex.Message}");
        }
    }

    // ---- API Key ----

    public bool HasApiKey => !string.IsNullOrEmpty(Current.Ai.ProtectedApiKey);

    /// <summary>保存 API Key（空白 = 清除）。只写入 DPAPI 密文。</summary>
    public Task SetApiKeyAsync(string? plainKey, CancellationToken ct = default)
    {
        var protectedKey = string.IsNullOrWhiteSpace(plainKey) ? null : _protector.Protect(plainKey.Trim());
        return UpdateAsync(s => s with { Ai = s.Ai with { ProtectedApiKey = protectedKey } }, ct);
    }

    /// <summary>取出明文 Key（仅在发请求时短暂使用）；未设置或无法解密返回 null。</summary>
    public string? TryGetApiKey()
    {
        var cipher = Current.Ai.ProtectedApiKey;
        if (string.IsNullOrEmpty(cipher)) return null;
        try
        {
            return _protector.Unprotect(cipher);
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException or FormatException)
        {
            // 换了 Windows 账户/机器后密文无法解密：按“未设置”处理，由界面提示重新输入
            AppLog.Warn("API Key 无法解密（可能来自其他 Windows 账户或机器），请重新输入");
            return null;
        }
    }

    /// <summary>用于界面展示的掩码，如 “sk-••••••abcd”。未设置返回空串。</summary>
    public string MaskedApiKey()
    {
        var key = TryGetApiKey();
        if (string.IsNullOrEmpty(key)) return "";
        return key.Length <= 8 ? new string('•', key.Length) : $"{key[..3]}{new string('•', 6)}{key[^4..]}";
    }
}
