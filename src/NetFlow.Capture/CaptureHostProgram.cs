using NetFlow.Windows;

namespace NetFlow.Capture;

/// <summary>
/// 提权采集宿主入口逻辑。设计文档 4.5 采集闭环：
/// 按参数启动 Pktmon，等待停止条件（时长/命名事件/停止文件），停止并转换，
/// 记录版本/过滤器/退出码，状态文件输出。转换失败时保留 ETL。
///
/// 语法自适应（M0 OS 能力矩阵）：不同 Windows 版本的 pktmon 命令差异较大——
/// - 启动：新版 `start --capture --pkt-size N --file-name X`；旧版 `start --etw -f X [-p N]`
/// - 过滤：部分版本要求 `filter add <name> -i <ip>` 带名称
/// - drop 转换：新版 `etl2pcap --drop-only`
/// 每个候选命令按序尝试，全部退出码如实记录，不虚构能力。
/// </summary>
public static class CaptureHostProgram
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var paramsIndex = Array.IndexOf(args, "--params");
        if (paramsIndex < 0 || paramsIndex + 1 >= args.Length)
        {
            Console.Error.WriteLine("缺少 --params <file>");
            return 2;
        }

        var paramsFile = args[paramsIndex + 1];
        CaptureParams? parameters;
        try
        {
            if (!File.Exists(paramsFile))
            {
                Console.Error.WriteLine($"参数文件不存在：{paramsFile}");
                return 2;
            }
            parameters = CaptureParams.FromJson(File.ReadAllText(paramsFile));
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"参数文件读取失败：{ex.Message}");
            return 2;
        }
        if (parameters is null)
        {
            Console.Error.WriteLine("参数文件解析失败");
            return 2;
        }

        var errors = parameters.Validate(paramsFile);
        if (errors.Count > 0)
        {
            Console.Error.WriteLine("参数校验失败：" + string.Join("; ", errors));
            return 2;
        }

        var statusPath = Path.Combine(parameters.WorkingDirectory, "capture-status.json");
        var etlPath = Path.Combine(parameters.WorkingDirectory, $"capture-{parameters.RunId}.etl");
        var pcapngPath = Path.Combine(parameters.WorkingDirectory, $"capture-{parameters.RunId}.pcapng");
        var dropPath = Path.Combine(parameters.WorkingDirectory, $"drop-{parameters.RunId}.pcapng");
        var stopFile = Path.Combine(parameters.WorkingDirectory, "stop.now");
        var exitCodes = new Dictionary<string, string>();

        var status = new CaptureStatus
        {
            Phase = "started", StartedUtc = DateTimeOffset.UtcNow, Mode = parameters.Mode,
        };
        try
        {
            status.WriteTo(statusPath);
        }
        catch (IOException ex)
        {
            Console.Error.WriteLine($"状态文件不可写（{statusPath}）：{ex.Message}");
            return 2;
        }

        try
        {
            // 版本记录（旧版无 --version，用 help 输出首行代替；失败不阻断）
            var versionRun = await ProcessRunner.RunAsync(
                ProcessRunner.PktmonPath, ["--version"], TimeSpan.FromSeconds(10), ct)
                .ConfigureAwait(false);
            var versionText = versionRun.StandardOutput.Trim() is { Length: > 0 } v &&
                              !v.Contains("未知命令") && !v.Contains("unknown command")
                ? v
                : (await ProcessRunner.RunAsync(
                    ProcessRunner.PktmonPath, ["help"], TimeSpan.FromSeconds(10), ct)
                    .ConfigureAwait(false)).StandardOutput.Split('\n').FirstOrDefault()?.Trim() ?? "";
            status = status with
            {
                PktmonVersion = versionText.Length > 0 ? versionText[..Math.Min(120, versionText.Length)] : "未知",
            };
            exitCodes["version"] = versionRun.ExitCode.ToString();

            // 过滤器（目标 IP 优先；语法自适应：带名/不带名）
            if (parameters.TargetIp is { } ip)
            {
                var filterRemove = await RunPktmon(["filter", "remove"], ct).ConfigureAwait(false);
                exitCodes["filter-remove"] = filterRemove.ExitCode.ToString();

                var filter = await TryFilterAddAsync(ip, exitCodes, ct).ConfigureAwait(false);
                if (filter is null)
                {
                    throw new InvalidOperationException(
                        $"无法设置抓包过滤器（退出码 {exitCodes.GetValueOrDefault("filter-add#0", "?")}）");
                }
            }

            // 实时模式：pktmon 实时输出写入 live.log，不产生 ETL/PCAPNG
            if (parameters.Mode == CaptureParams.LiveMode)
            {
                return await RunLiveAsync(
                    parameters, status, statusPath, stopFile, exitCodes, ct).ConfigureAwait(false);
            }

            // 启动采集（语法自适应：新版 capture / 旧版 etw）
            var start = await TryStartCaptureAsync(
                etlPath, parameters.SnapLengthBytes, exitCodes, ct).ConfigureAwait(false);
            if (start is null)
            {
                throw new InvalidOperationException(
                    $"无法启动 Pktmon（退出码 {exitCodes.GetValueOrDefault("start#0", "?")}）。" +
                    "请检查 Pktmon 是否可用。");
            }

            status = status with { Phase = "running" };
            status.WriteTo(statusPath);

            await WaitForStopAsync(parameters, stopFile, ct).ConfigureAwait(false);

            status = status with { Phase = "stopping" };
            status.WriteTo(statusPath);

            // 停止
            var stop = await RunPktmon(["stop"], ct).ConfigureAwait(false);
            exitCodes["stop"] = stop.ExitCode.ToString();
            status = status with { StoppedUtc = DateTimeOffset.UtcNow };

            // 转换 PCAPNG（全部流量 + drop-only，语法按版本自适应）
            var convert = await RunPktmon(
                ["etl2pcap", etlPath, "--out", pcapngPath], ct).ConfigureAwait(false);
            if (!convert.Succeeded)
            {
                convert = await RunPktmon(
                    ["etl2pcap", etlPath, "-o", pcapngPath], ct).ConfigureAwait(false);
            }
            exitCodes["etl2pcap"] = convert.ExitCode.ToString();

            var dropConvert = await RunPktmon(
                ["etl2pcap", etlPath, "--out", dropPath, "--drop-only"], ct).ConfigureAwait(false);
            if (!dropConvert.Succeeded)
            {
                dropConvert = await RunPktmon(
                    ["etl2pcap", etlPath, "-o", dropPath, "--drop-only"], ct).ConfigureAwait(false);
            }
            exitCodes["etl2pcap-drop"] = dropConvert.ExitCode.ToString();

            // 清理本工具的过滤器（不触碰外部抓包会话）
            var filterCleanup = await RunPktmon(["filter", "remove"], ct).ConfigureAwait(false);
            exitCodes["filter-cleanup"] = filterCleanup.ExitCode.ToString();

            var pcapngProduced = File.Exists(pcapngPath);
            status = status with
            {
                Phase = "finished",
                PcapngPath = pcapngProduced ? pcapngPath : null,
                DropPcapngPath = File.Exists(dropPath) ? dropPath : null,
                EtlPath = File.Exists(etlPath) ? etlPath : null,
                ExitCode = stop.ExitCode,
                ExitCodes = exitCodes,
                // 转换失败必须显式可见，不能只留一个空 PcapngPath 让上游猜
                Error = pcapngProduced
                    ? null
                    : $"未能生成 PCAPNG（etl2pcap 退出码 {convert.ExitCode}）。原始 ETL 文件已保留。",
            };
            status.WriteTo(statusPath);
            return 0;
        }
        catch (Exception ex)
        {
            // 启动失败/转换失败：保留 ETL 作为高级诊断证据
            status = status with
            {
                Phase = "failed",
                Error = ex.Message,
                EtlPath = File.Exists(etlPath) ? etlPath : null,
                ExitCodes = exitCodes,
            };
            status.WriteTo(statusPath);
            return 1;
        }
    }

    /// <summary>等待停止条件：命名事件 / 停止文件 / 最长时长 / 外部取消。</summary>
    private static async Task WaitForStopAsync(
        CaptureParams parameters, string stopFile, CancellationToken ct)
    {
        var startUtc = DateTimeOffset.UtcNow;
        var maxDuration = TimeSpan.FromSeconds(parameters.MaxDurationSeconds);
        EventWaitHandle? stopEvent = null;
        try
        {
            // 事件由主程序预先创建并保持句柄；宿主兜底自建（同会话 Local\ 可创建）
            if (!EventWaitHandle.TryOpenExisting(parameters.StopEventName, out stopEvent))
            {
                stopEvent = new EventWaitHandle(false, EventResetMode.ManualReset, parameters.StopEventName);
            }
        }
        catch (Exception)
        {
            stopEvent = null; // 事件通道不可用 → 停止文件 + 时长兜底
        }

        try
        {
            while (true)
            {
                if (ct.IsCancellationRequested) break;
                if (stopEvent is not null && stopEvent.WaitOne(500)) break;
                if (stopEvent is null) await Task.Delay(500, ct).ConfigureAwait(false);
                if (File.Exists(stopFile)) break;
                if (DateTimeOffset.UtcNow - startUtc >= maxDuration) break;
            }
        }
        finally
        {
            stopEvent?.Dispose();
        }
    }

    /// <summary>实时模式的 ETL 缓冲文件名（位于任务目录，停止后删除）。</summary>
    public const string LiveBufferFileName = "live-buffer.etl";

    /// <summary>实时模式的 pktmon 启动参数：缓冲文件限定在任务目录，且最大 16 MB。</summary>
    public static IReadOnlyList<string> BuildLiveStartArgs(int snapLengthBytes, string bufferPath) =>
    [
        "start", "--capture", "--pkt-size", snapLengthBytes.ToString(),
        "--log-mode", "real-time",
        "--file-name", bufferPath, "--file-size", "16",
    ];

    /// <summary>live.log 大小上限：超出后停止追加，避免高流量下写满磁盘。</summary>
    private const long MaxLiveLogBytes = 64L * 1024 * 1024;

    /// <summary>
    /// 实时模式：<c>pktmon start --capture --log-mode real-time</c> 会一直运行并把数据包打印到标准输出，
    /// 宿主把输出逐行写入 live.log；停止条件与记录模式一致，停止时执行 <c>pktmon stop</c>。
    /// pktmon 输出含本地化文字，按 Latin-1 逐字节读写以保证 ASCII 部分不被破坏。
    /// </summary>
    private static async Task<int> RunLiveAsync(
        CaptureParams parameters, CaptureStatus status, string statusPath, string stopFile,
        Dictionary<string, string> exitCodes, CancellationToken ct)
    {
        var livePath = Path.Combine(parameters.WorkingDirectory, "live.log");
        // pktmon 实时模式仍会创建 ETL 缓冲文件（默认 PktMon.etl，最大 512 MB，写在进程工作目录）：
        // 限定在任务目录内、限制大小，停止后删除
        var bufferPath = Path.Combine(parameters.WorkingDirectory, LiveBufferFileName);
        var psi = new System.Diagnostics.ProcessStartInfo(ProcessRunner.PktmonPath)
        {
            WorkingDirectory = parameters.WorkingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = System.Text.Encoding.Latin1,
            StandardErrorEncoding = System.Text.Encoding.Latin1,
        };
        foreach (var a in BuildLiveStartArgs(parameters.SnapLengthBytes, bufferPath))
            psi.ArgumentList.Add(a);

        using var process = System.Diagnostics.Process.Start(psi)
            ?? throw new InvalidOperationException("pktmon 实时模式启动失败（系统未返回进程句柄）");

        var errorText = new System.Text.StringBuilder();
        var pump = Task.Run(async () =>
        {
            await using var fs = new FileStream(livePath, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
            await using var writer = new StreamWriter(fs, System.Text.Encoding.Latin1) { AutoFlush = true };
            long written = 0;
            while (await process.StandardOutput.ReadLineAsync().ConfigureAwait(false) is { } line)
            {
                if (written > MaxLiveLogBytes) continue; // 超限后继续消费输出但不再落盘
                await writer.WriteLineAsync(line).ConfigureAwait(false);
                written += line.Length + 2;
            }
        }, CancellationToken.None);
        var errPump = Task.Run(async () =>
        {
            while (await process.StandardError.ReadLineAsync().ConfigureAwait(false) is { } line)
                if (errorText.Length < 2000) errorText.AppendLine(line);
        }, CancellationToken.None);

        // 启动即失败（语法不被支持、已有会话在运行等）立刻暴露，而不是让界面一直显示“抓包中”
        await Task.Delay(1500, ct).ConfigureAwait(false);
        if (process.HasExited)
        {
            exitCodes["start-live"] = process.ExitCode.ToString();
            await Task.WhenAll(pump, errPump).ConfigureAwait(false);
            throw new InvalidOperationException(
                $"Pktmon 实时模式启动后立即退出（退出码 {process.ExitCode}）：" +
                (errorText.Length > 0 ? errorText.ToString().Trim() : "当前系统版本可能不支持实时模式"));
        }

        status = status with { Phase = "running" };
        status.WriteTo(statusPath);

        await WaitForStopAsync(parameters, stopFile, ct).ConfigureAwait(false);

        status = status with { Phase = "stopping" };
        status.WriteTo(statusPath);

        var stop = await RunPktmon(["stop"], ct).ConfigureAwait(false);
        exitCodes["stop"] = stop.ExitCode.ToString();
        status = status with { StoppedUtc = DateTimeOffset.UtcNow };

        if (!process.WaitForExit(8000))
        {
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { /* 已退出 */ }
        }
        try
        {
            await Task.WhenAll(pump, errPump).WaitAsync(TimeSpan.FromSeconds(5), CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            // 输出泵未能及时结束：不阻塞收尾，已落盘的内容仍可读
        }

        var cleanup = await RunPktmon(["filter", "remove"], ct).ConfigureAwait(false);
        exitCodes["filter-cleanup"] = cleanup.ExitCode.ToString();

        // 缓冲文件不是产物，删除以免占用磁盘（失败不影响结果）
        try { File.Delete(bufferPath); } catch (IOException) { /* 仍被占用时保留，随任务目录清理 */ }

        status = status with
        {
            Phase = "finished",
            ExitCode = stop.ExitCode,
            ExitCodes = exitCodes,
            Error = null,
        };
        status.WriteTo(statusPath);
        return 0;
    }

    /// <summary>构建启动参数候选（按版本概率排序）。</summary>
    internal static List<List<string>> BuildStartArgCandidates(string etlPath, int snapLengthBytes) =>
    [
        // 新版（Win11 21H2+/Server 2022+）
        snapLengthBytes > 0
            ? ["start", "--capture", "--pkt-size", snapLengthBytes.ToString(), "--file-name", etlPath]
            : ["start", "--capture", "--pkt-size", "0", "--file-name", etlPath],
        // 旧版（--etw 文件模式）
        snapLengthBytes > 0
            ? ["start", "--etw", "-f", etlPath, "-p", snapLengthBytes.ToString()]
            : ["start", "--etw", "-f", etlPath],
    ];

    /// <summary>依次尝试各候选启动语法；全部失败返回 null。</summary>
    private static async Task<ProcessRunResult?> TryStartCaptureAsync(
        string etlPath, int snapLengthBytes,
        Dictionary<string, string> exitCodes, CancellationToken ct)
    {
        ProcessRunResult? last = null;
        int index = 0;
        foreach (var args in BuildStartArgCandidates(etlPath, snapLengthBytes))
        {
            last = await RunPktmon(args, ct).ConfigureAwait(false);
            exitCodes[$"start#{index}"] = last.ExitCode.ToString();
            if (last.Succeeded) return last;
            // 启动失败后先 stop 复位，避免下一候选被“已在运行”挡住
            var reset = await RunPktmon(["stop"], ct).ConfigureAwait(false);
            exitCodes[$"start#{index}-reset"] = reset.ExitCode.ToString();
            index++;
        }
        return last?.Succeeded == true ? last : null;
    }

    /// <summary>过滤器添加：部分版本要求带名称。全部失败返回 null。</summary>
    private static async Task<ProcessRunResult?> TryFilterAddAsync(
        string ip, Dictionary<string, string> exitCodes, CancellationToken ct)
    {
        ProcessRunResult? last = null;
        IReadOnlyList<string> withName = ["filter", "add", "netflow", "-i", ip]; // 新版要求 <name>
        IReadOnlyList<string> withoutName = ["filter", "add", "-i", ip];         // 旧版不带名
        var candidates = new[] { withName, withoutName };
        int index = 0;
        foreach (var args in candidates)
        {
            last = await RunPktmon(args, ct).ConfigureAwait(false);
            exitCodes[$"filter-add#{index}"] = last.ExitCode.ToString();
            if (last.Succeeded) return last;
            index++;
        }
        return last?.Succeeded == true ? last : null;
    }

    private static async Task<ProcessRunResult> RunPktmon(
        IReadOnlyList<string> args, CancellationToken ct) =>
        await ProcessRunner.RunAsync(
            ProcessRunner.PktmonPath, args, TimeSpan.FromMinutes(5), ct).ConfigureAwait(false);
}
