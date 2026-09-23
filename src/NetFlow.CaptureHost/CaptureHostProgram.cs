using NetFlow.Capture;
using NetFlow.Windows;

namespace NetFlow.CaptureHost;

/// <summary>
/// 提权采集宿主入口逻辑。设计文档 4.5 采集闭环：
/// 按参数启动 Pktmon，等待停止条件（时长/命名事件/停止文件），停止并转换，
/// 记录版本/过滤器/退出码，状态文件输出。转换失败时保留 ETL。
/// 安全约束：只接受位于工作目录内的参数文件；写入范围限定在工作目录。
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

        var status = new CaptureStatus { Phase = "started", StartedUtc = DateTimeOffset.UtcNow };
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
            // 版本记录（失败不阻断：版本未知仍可采集，退出码如实记录）
            var versionRun = await ProcessRunner.RunAsync(
                ProcessRunner.PktmonPath, ["--version"], TimeSpan.FromSeconds(10), ct)
                .ConfigureAwait(false);
            status = status with
            {
                PktmonVersion = versionRun.StandardOutput.Trim() is { Length: > 0 } v
                    ? v
                    : $"（--version 退出码 {versionRun.ExitCode}）",
            };
            exitCodes["version"] = versionRun.ExitCode.ToString();

            // 过滤器
            if (parameters.TargetIp is { } ip)
            {
                var filterRemove = await RunPktmon(["filter", "remove"], ct).ConfigureAwait(false);
                exitCodes["filter-remove"] = filterRemove.ExitCode.ToString();
                var filter = await RunPktmon(["filter", "add", "-i", ip], ct).ConfigureAwait(false);
                exitCodes["filter-add"] = filter.ExitCode.ToString();
                if (!filter.Succeeded)
                {
                    throw new InvalidOperationException(
                        $"过滤器添加失败（exit {filter.ExitCode}）：{filter.StandardError.Trim()}");
                }
            }

            // 启动采集（截断长度等参数按 pktmon 各版本能力，失败路径如实记录）
            var startArgs = new List<string> { "start", "--etw", "-f", etlPath };
            if (parameters.SnapLengthBytes > 0)
            {
                startArgs.AddRange(["-p", parameters.SnapLengthBytes.ToString()]);
            }
            var start = await RunPktmon([.. startArgs], ct).ConfigureAwait(false);
            exitCodes["start"] = start.ExitCode.ToString();
            if (!start.Succeeded)
            {
                throw new InvalidOperationException(
                    $"pktmon start 失败（exit {start.ExitCode}）：{start.StandardError.Trim()}");
            }

            status = status with { Phase = "running" };
            status.WriteTo(statusPath);

            // 等待停止条件：命名事件 / 停止文件 / 最长时长 / 外部取消
            var startUtc = DateTimeOffset.UtcNow;
            var maxDuration = TimeSpan.FromSeconds(parameters.MaxDurationSeconds);
            EventWaitHandle? stopEvent = null;
            try
            {
                // 事件由主程序预先创建；宿主兜底自建（同会话 Local\ 可创建）
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

            status = status with { Phase = "stopping" };
            status.WriteTo(statusPath);

            // 停止（即使 filter/start 阶段成功，stop 失败也要如实呈现）
            var stop = await RunPktmon(["stop"], ct).ConfigureAwait(false);
            exitCodes["stop"] = stop.ExitCode.ToString();
            status = status with { StoppedUtc = DateTimeOffset.UtcNow };

            // 转换 PCAPNG（正常通信 + drop-only）
            var convert = await RunPktmon(
                ["etl2pcap", etlPath, "-o", pcapngPath], ct).ConfigureAwait(false);
            exitCodes["etl2pcap"] = convert.ExitCode.ToString();
            var dropConvert = await RunPktmon(
                ["etl2pcap", etlPath, "--type", "drop", "-o", dropPath], ct).ConfigureAwait(false);
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
                    : $"PCAPNG 转换未产出（etl2pcap exit {convert.ExitCode}）；ETL 原始证据已保留供高级诊断",
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

    private static async Task<ProcessRunResult> RunPktmon(
        IReadOnlyList<string> args, CancellationToken ct) =>
        await ProcessRunner.RunAsync(
            ProcessRunner.PktmonPath, args, TimeSpan.FromMinutes(5), ct).ConfigureAwait(false);
}
