using NetFlow.Capture;
using NetFlow.Windows;

namespace NetFlow.CaptureHost;

/// <summary>
/// 提权采集宿主入口逻辑。设计文档 4.5 采集闭环：
/// 按参数启动 Pktmon，等待停止条件（时长/停止事件），停止并转换，
/// 记录版本/过滤器/退出码，状态文件输出。转换失败时保留 ETL。
/// </summary>
public static class CaptureHostProgram
{
    public static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        // 参数解析
        var paramsIndex = Array.IndexOf(args, "--params");
        if (paramsIndex < 0 || paramsIndex + 1 >= args.Length)
        {
            Console.Error.WriteLine("缺少 --params <file>");
            return 2;
        }
        var parameters = CaptureParams.FromJson(File.ReadAllText(args[paramsIndex + 1]));
        if (parameters is null)
        {
            Console.Error.WriteLine("参数文件解析失败");
            return 2;
        }
        var errors = parameters.Validate();
        if (errors.Count > 0)
        {
            Console.Error.WriteLine("参数校验失败：" + string.Join("; ", errors));
            return 2;
        }

        var statusPath = Path.Combine(parameters.WorkingDirectory, "capture-status.json");
        var etlPath = Path.Combine(parameters.WorkingDirectory, $"capture-{parameters.RunId}.etl");
        var pcapngPath = Path.Combine(parameters.WorkingDirectory, $"capture-{parameters.RunId}.pcapng");
        var dropPath = Path.Combine(parameters.WorkingDirectory, $"drop-{parameters.RunId}.pcapng");
        var exitCodes = new Dictionary<string, string>();

        var status = new CaptureStatus { Phase = "started", StartedUtc = DateTimeOffset.UtcNow };
        status.WriteTo(statusPath);

        // 版本记录
        var versionRun = await ProcessRunner.RunAsync(
            ProcessRunner.PktmonPath, ["--version"], TimeSpan.FromSeconds(10), ct)
            .ConfigureAwait(false);
        status = status with
        {
            PktmonVersion = versionRun.StandardOutput.Trim() is { Length: > 0 } v ? v : "未知",
        };

        try
        {
            // 过滤器
            if (parameters.TargetIp is { } ip)
            {
                var filter = await RunPktmon(["filter", "remove"], ct).ConfigureAwait(false);
                exitCodes["filter-remove"] = filter.ExitCode.ToString();
                filter = await RunPktmon(["filter", "add", "-i", ip], ct).ConfigureAwait(false);
                exitCodes["filter-add"] = filter.ExitCode.ToString();
                if (!filter.Succeeded)
                    throw new InvalidOperationException($"过滤器添加失败（exit {filter.ExitCode}）：{filter.StandardError.Trim()}");
            }

            // 启动采集（组件 all + 限定缓冲与截断由 pktmon 各版本能力决定；失败路径如实记录）
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

            // 等待停止条件
            var startUtc = DateTimeOffset.UtcNow;
            var maxDuration = TimeSpan.FromSeconds(parameters.MaxDurationSeconds);
            EventWaitHandle? stopEvent = EventWaitHandle.OpenExisting(parameters.StopEventName);

            while (true)
            {
                if (ct.IsCancellationRequested) break;
                if (stopEvent is not null && stopEvent.WaitOne(500)) break;
                else if (stopEvent is null) await Task.Delay(500, ct).ConfigureAwait(false);
                if (DateTimeOffset.UtcNow - startUtc >= maxDuration) break;
            }

            status = status with { Phase = "stopping" };
            status.WriteTo(statusPath);

            // 停止
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

            // 清理过滤器（不触碰外部抓包会话）
            _ = await RunPktmon(["filter", "remove"], ct).ConfigureAwait(false);

            status = status with
            {
                Phase = "finished",
                PcapngPath = File.Exists(pcapngPath) ? pcapngPath : null,
                DropPcapngPath = File.Exists(dropPath) ? dropPath : null,
                EtlPath = File.Exists(etlPath) ? etlPath : null,
                ExitCode = stop.ExitCode,
                ExitCodes = exitCodes,
            };
            status.WriteTo(statusPath);
            return 0;
        }
        catch (Exception ex)
        {
            // 转换失败/启动失败：保留 ETL 作为高级诊断证据
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
