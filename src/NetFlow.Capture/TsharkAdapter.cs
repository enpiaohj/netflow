using NetFlow.Windows;

namespace NetFlow.Capture;

/// <summary>TShark 可用性。</summary>
public sealed record TsharkCapability
{
    public bool Available { get; init; }
    public string? Path { get; init; }
    public string? Version { get; init; }
    public string? Error { get; init; }
}

/// <summary>
/// TShark 可选适配（设计文档 4.5）：仅调用用户已安装的可执行文件做深层离线解析，
/// 不捆绑分发、不当默认抓包后端。做路径/版本检测和超时限制。
/// </summary>
public static class TsharkAdapter
{
    private static readonly string[] CandidatePaths =
    [
        @"C:\Program Files\Wireshark\tshark.exe",
        @"C:\Program Files (x86)\Wireshark\tshark.exe",
    ];

    public static async Task<TsharkCapability> DetectAsync(CancellationToken ct = default)
    {
        foreach (var candidate in CandidatePaths)
        {
            if (!File.Exists(candidate)) continue;
            try
            {
                var version = await ProcessRunner.RunAsync(
                    candidate, ["--version"], TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
                if (version.Succeeded)
                {
                    // 首行形如 TShark (Wireshark) 4.2.3 (v4.2.3-0-...)
                    var first = version.StandardOutput.Split('\n').FirstOrDefault()?.Trim();
                    return new TsharkCapability
                    {
                        Available = true,
                        Path = candidate,
                        Version = first,
                    };
                }
            }
            catch (Exception ex)
            {
                return new TsharkCapability { Available = false, Error = ex.Message };
            }
        }
        return new TsharkCapability
        {
            Available = false,
            Error = "未检测到 TShark（可选组件，不影响 Pktmon 抓包与内置分析）",
        };
    }

    /// <summary>
    /// 深度解析：tshark -r 文件，输出协议层级统计与详细字段。
    /// 返回（协议统计，详细前 N 行）。
    /// </summary>
    public static async Task<(string ProtocolHierarchy, string Detail)> DeepAnalyzeAsync(
        string pcapngPath, int maxDetailLines = 300, CancellationToken ct = default)
    {
        var capability = await DetectAsync(ct).ConfigureAwait(false);
        if (!capability.Available)
            throw new InvalidOperationException(capability.Error ?? "TShark 不可用");

        var ioPhs = await ProcessRunner.RunAsync(
            capability.Path!,
            ["-r", pcapngPath, "-q", "-z", "io,phs"],
            TimeSpan.FromMinutes(5), ct).ConfigureAwait(false);

        var detail = await ProcessRunner.RunAsync(
            capability.Path!,
            ["-r", pcapngPath, "-V"],
            TimeSpan.FromMinutes(10), ct).ConfigureAwait(false);

        var detailLines = detail.StandardOutput
            .Split('\n')
            .Take(maxDetailLines)
            .ToArray();

        return (
            ioPhs.StandardOutput.Trim(),
            string.Join('\n', detailLines) +
                (detail.StandardOutput.Split('\n').Length > maxDetailLines
                    ? "\n…[详细输出已截断，完整内容可用 Wireshark 打开原始文件]"
                    : ""));
    }
}
