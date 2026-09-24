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

    public const string RecordMode = "record";
    public const string LiveMode = "live";

    /// <summary>
    /// 采集模式：record = 记录到 ETL 并转换为 PCAPNG（默认）；
    /// live = pktmon 实时模式，输出写入 live.log 供界面实时显示，不产生 ETL/PCAPNG。
    /// </summary>
    public string Mode { get; init; } = RecordMode;

    /// <summary>宿主工作目录（限定写入范围）。</summary>
    public required string WorkingDirectory { get; init; }

    /// <summary>停止事件名（Global\ 前缀）。</summary>
    public required string StopEventName { get; init; }

    public string ToJson() => JsonSerializer.Serialize(this, JsonOpts);

    public static CaptureParams? FromJson(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<CaptureParams>(json, JsonOpts);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = false,
    };

    /// <summary>宿主侧参数校验。非法输入直接拒绝，不做默认修正。</summary>
    public IReadOnlyList<string> Validate(string? paramsFilePath = null)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(RunId) ||
            !System.Text.RegularExpressions.Regex.IsMatch(RunId, @"^[0-9a-fA-F-]{8,40}$"))
            errors.Add("RunId 格式非法（应为 8–40 位十六进制/连字符）");

        if (TargetIp is not null &&
            !System.Net.IPAddress.TryParse(TargetIp, out _))
            errors.Add("TargetIp 不是合法 IP 地址");

        if (RingBufferMb is < 16 or > 1024)
            errors.Add("环形缓冲区超出允许范围 16–1024 MB");
        if (MaxDurationSeconds is < 10 or > 3600)
            errors.Add("最长采集时长超出允许范围 10–3600 秒");
        if (SnapLengthBytes is < 0 or > 1514)
            errors.Add("截断长度非法");
        if (Mode is not (RecordMode or LiveMode))
            errors.Add("采集模式非法（应为 record 或 live）");
        if (string.IsNullOrWhiteSpace(WorkingDirectory) || !Directory.Exists(WorkingDirectory))
            errors.Add("工作目录不存在");
        if (string.IsNullOrWhiteSpace(StopEventName) || StopEventName.Length > 200)
            errors.Add("停止事件名非法");

        // 提权宿主的写入范围限定：参数文件必须位于工作目录内，
        // 防止任意目录写入（设计文档 2.1：按任务 ID 写入限定工作目录）
        if (paramsFilePath is not null &&
            !string.IsNullOrWhiteSpace(WorkingDirectory) &&
            Directory.Exists(WorkingDirectory))
        {
            string fullParams, fullWork;
            try
            {
                fullParams = Path.GetFullPath(paramsFilePath);
                fullWork = Path.GetFullPath(WorkingDirectory)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                    + Path.DirectorySeparatorChar;
            }
            catch (Exception)
            {
                errors.Add("路径解析失败");
                return errors;
            }
            if (!fullParams.StartsWith(fullWork, StringComparison.OrdinalIgnoreCase))
                errors.Add("参数文件必须位于工作目录内（写入范围限定）");
        }

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

    /// <summary>采集模式（record/live）。实时模式没有 PCAPNG 产物属正常情况。</summary>
    public string Mode { get; init; } = CaptureParams.RecordMode;

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
