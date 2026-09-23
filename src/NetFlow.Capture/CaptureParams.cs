using System.Text.Json;

namespace NetFlow.Capture;

/// <summary>
/// 采集参数（主程序 → 提权宿主的唯一输入）。宿主只接受经过校验的参数
/// （设计文档 2.1），字段全部有界。
/// </summary>
public sealed record CaptureParams
{
    /// <summary>任务 ID（runId）。用作目录名，格式受限。</summary>
    public required string RunId { get; init; }

    /// <summary>过滤目标 IP（null = 全部流量，需显式确认范围）。</summary>
    public string? TargetIp { get; init; }

    /// <summary>环形缓冲区上限（MB）。</summary>
    public int RingBufferMb { get; init; } = 256;

    /// <summary>最长采集时长（秒）。</summary>
    public int MaxDurationSeconds { get; init; } = 600;

    /// <summary>每包截断长度（字节，0 = 完整包）。</summary>
    public int SnapLengthBytes { get; init; } = 128;

    /// <summary>宿主工作目录（限定写入范围）。</summary>
    public required string WorkingDirectory { get; init; }

    /// <summary>停止事件名（Global\ 前缀）。</summary>
    public required string StopEventName { get; init; }

    public string ToJson() => JsonSerializer.Serialize(this, JsonOpts);

    public static CaptureParams? FromJson(string json) =>
        JsonSerializer.Deserialize<CaptureParams>(json, JsonOpts);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
    };

    /// <summary>宿主侧参数校验。非法输入直接拒绝，不做默认修正。</summary>
    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (!System.Text.RegularExpressions.Regex.IsMatch(RunId, @"^[0-9a-fA-F-]{8,40}$"))
            errors.Add("RunId 格式非法");
        if (RingBufferMb is < 16 or > 1024)
            errors.Add("环形缓冲区超出允许范围 16–1024 MB");
        if (MaxDurationSeconds is < 10 or > 3600)
            errors.Add("最长采集时长超出允许范围 10–3600 秒");
        if (SnapLengthBytes is < 0 or > 1514)
            errors.Add("截断长度非法");
        if (!Directory.Exists(WorkingDirectory))
            errors.Add("工作目录不存在");
        if (StopEventName.Length is 0 or > 200)
            errors.Add("停止事件名非法");
        return errors;
    }
}

/// <summary>宿主状态文件内容（宿主 → 主程序单向输出）。</summary>
public sealed record CaptureStatus
{
    public string Phase { get; init; } = "unknown"; // started/running/stopping/finished/failed
    public string? PktmonVersion { get; init; }
    public DateTimeOffset? StartedUtc { get; init; }
    public DateTimeOffset? StoppedUtc { get; init; }
    public string? PcapngPath { get; init; }
    public string? DropPcapngPath { get; init; }
    public string? EtlPath { get; init; }
    public string? Error { get; init; }
    public int ExitCode { get; init; }
    public IReadOnlyDictionary<string, string> ExitCodes { get; init; } =
        new Dictionary<string, string>();

    public void WriteTo(string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            WriteIndented = true,
        }));

    public static CaptureStatus? ReadFrom(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return JsonSerializer.Deserialize<CaptureStatus>(File.ReadAllText(path));
        }
        catch
        {
            return null;
        }
    }
}
