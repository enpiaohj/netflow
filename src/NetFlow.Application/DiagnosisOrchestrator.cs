using System.Net;
using NetFlow.Domain;
using NetFlow.Probes;

namespace NetFlow.Application;

/// <summary>诊断请求。</summary>
public sealed record DiagnosisRequest
{
    public required string RequestedTarget { get; init; }

    /// <summary>场景模板 ID；null = 自由测试（用 StepsOverride）。</summary>
    public string? ScenarioId { get; init; }

    /// <summary>用户自定义模板（优先于 ScenarioId 查找内置表）。</summary>
    public ScenarioTemplate? CustomTemplate { get; init; }

    /// <summary>自由测试时的探针清单。</summary>
    public IReadOnlyList<ScenarioStep>? StepsOverride { get; init; }

    /// <summary>指定源地址（null = 系统路由选择）。</summary>
    public IPAddress? SourceAddress { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>DNS 查询使用的域占位符 {domain} 替换值。</summary>
    public string? DomainName { get; init; }

    /// <summary>LDAP 绑定模式与凭据。</summary>
    public LdapBindMode LdapBindMode { get; init; } = LdapBindMode.CurrentIdentity;

    public System.Net.NetworkCredential? ExplicitCredential { get; init; }

    /// <summary>SQL 参数。</summary>
    public string? SqlInstanceName { get; init; }

    public int? SqlFixedPort { get; init; }

    public bool TrySqlLogin { get; init; }

    public System.Net.NetworkCredential? SqlCredential { get; init; }

    /// <summary>HTTP 选项。</summary>
    public bool HttpAllowInvalidTls { get; init; }

    /// <summary>ICMP 样本数。</summary>
    public int PingSamples { get; init; } = 4;
}

/// <summary>编排结果。</summary>
public sealed record DiagnosisOutcome
{
    public required DiagnosisRun Run { get; init; }
}

/// <summary>
/// 诊断任务编排器（设计文档 7.1 任务状态机）：
/// Draft → Preparing → Running → Finalizing → Completed / Failed /（Partial）。
/// 取消、崩溃、超时均保留部分结果并标记终止原因。
/// </summary>
public sealed class DiagnosisOrchestrator
{
    private readonly INameResolver _resolver;

    public DiagnosisOrchestrator(INameResolver? resolver = null)
    {
        _resolver = resolver ?? SystemNameResolver.Instance;
    }

    public event EventHandler<string>? StatusChanged;

    private void Report(string message) => StatusChanged?.Invoke(this, message);

    public async Task<DiagnosisOutcome> ExecuteAsync(
        DiagnosisRequest request,
        NetFlow.Persistence.DiagnosisRepository? repository = null,
        ITaskCaptureHook? capture = null,
        CancellationToken ct = default)
    {
        var run = new DiagnosisRun
        {
            SourceHost = Environment.MachineName,
            RequestedSourceAddress = request.SourceAddress?.ToString(),
            RequestedTarget = request.RequestedTarget,
            AppVersion = NetFlowInfo.Version,
        };

        try
        {
            // ---- Preparing ----
            run.StartUtc = DateTimeOffset.UtcNow;
            Report("准备中：解析目标与环境快照");

            var template = request.CustomTemplate ??
                (request.ScenarioId is null ? null : BuiltinTemplates.Find(request.ScenarioId));
            if (request.ScenarioId is not null && template is null)
                throw new InvalidOperationException($"未知场景模板：{request.ScenarioId}");

            run.Adapter = NetworkInterfaceHelper.GetPreferredAdapterName(request.SourceAddress);
            run.Elevated = NetworkInterfaceHelper.IsElevated();

            // 目标解析
            IReadOnlyList<IPAddress> resolved;
            if (IPAddress.TryParse(request.RequestedTarget, out var direct))
            {
                resolved = [direct];
            }
            else
            {
                resolved = await _resolver.ResolveAsync(request.RequestedTarget, ct).ConfigureAwait(false);
            }
            run.ResolvedAddresses = [.. resolved.Select(a => a.ToString())];
            var target = resolved.First();

            if (template is not null)
                run.Scenario = template.ToSnapshot();
            await CheckpointAsync(repository, run, ct).ConfigureAwait(false);

            // 采集启动（可选）
            string? captureNote = null;
            string? pcapngPath = null;
            if (capture is not null)
            {
                var (started, reason) = await capture.StartAsync(run.Id, target, ct).ConfigureAwait(false);
                captureNote = started ? "抓包已启动" : $"抓包未启动：{reason}";
                Report(captureNote);
            }

            // ---- Running ----
            Report($"执行中：{(template?.Name ?? "自由测试")}，{target}");
            var steps = template?.Steps ?? request.StepsOverride ?? [];
            var executor = new ProbeStepExecutor(request, _resolver);

            foreach (var step in steps)
            {
                ct.ThrowIfCancellationRequested();

                // 依赖条件：前序步骤的结论级别
                if (step.DependsOn.Count > 0 && step.RunWhenLevels.Count > 0)
                {
                    var depResults = run.Probes
                        .Where(p => step.DependsOn.Contains(p.Parameters.ProbeType.ToString()))
                        .ToList();
                    var levels = depResults
                        .Select(p => ConclusionEvaluator.Evaluate(p.Transport, p.Protocol).Level)
                        .ToList();
                    bool anyMatch = levels.Any(step.RunWhenLevels.Contains);
                    bool anyRan = depResults.Count > 0;
                    if (anyRan && !anyMatch)
                    {
                        run.AddSkippedStep(step, $"跳过条件满足：依赖步骤结论不在预期集合 " +
                            $"[{string.Join('/', step.RunWhenLevels)}]。{step.SkipReasonHint}");
                        continue;
                    }
                }

                var probeRun = await executor.ExecuteStepAsync(step, target, run.Id, ct)
                    .ConfigureAwait(false);
                run.Probes.Add(probeRun);
                run.Evidences.Add(EvidenceFactory.FromProbe(run.Id, probeRun));
                await CheckpointAsync(repository, run, ct).ConfigureAwait(false);
                Report($"完成：{step.Name} → {probeRun.Transport}/{probeRun.Protocol}");
            }

            // 远端服务查询（若模板含 RemoteServiceQuery 步骤则由 executor 处理；此处不默认）

            // 采集停止
            if (capture is not null)
            {
                var (path, note) = await capture.StopAsync(run.Id, ct).ConfigureAwait(false);
                pcapngPath = path;
                captureNote = note;
                if (path is not null)
                {
                    var fi = new FileInfo(path);
                    run.Artifacts.Add(new Artifact
                    {
                        RunId = run.Id,
                        Format = "pcapng",
                        AbsolutePath = path,
                        Size = fi.Exists ? fi.Length : 0,
                        Sha256 = fi.Exists ? FileHashSha256(path) : null,
                    });
                    run.Evidences.Add(new Evidence
                    {
                        RunId = run.Id,
                        Kind = EvidenceKind.PacketCaptureFile,
                        Side = SourceSide.Local,
                        CapturedUtc = DateTimeOffset.UtcNow,
                        ArtifactPath = path,
                        Summary = captureNote,
                        Redaction = RedactionLevel.Raw,
                    });
                }
                else if (captureNote is not null)
                {
                    run.AddObservationToAll(captureNote);
                }
            }

            // ---- Finalizing ----
            Report("生成结论与报告");
            run.Findings.AddRange(FindingFactory.CreateFindings(run, template));
            run.EndUtc = DateTimeOffset.UtcNow;

            if (repository is not null)
                await repository.SaveRunAsync(run, ct).ConfigureAwait(false);

            Report($"完成：{run.Probes.Count} 项检查");
            return new DiagnosisOutcome { Run = run };
        }
        catch (OperationCanceledException)
        {
            run.TerminationReason = "用户取消";
            run.EndUtc = DateTimeOffset.UtcNow;
            run.Findings.AddRange(FindingFactory.CreateFindings(run, null, canceled: true));
            if (repository is not null)
                await repository.SaveRunAsync(run, CancellationToken.None).ConfigureAwait(false);
            run.State = RunState.Canceled;
            return new DiagnosisOutcome { Run = run };
        }
        catch (Exception ex)
        {
            run.TerminationReason = $"执行失败：{ex.Message}";
            run.EndUtc = DateTimeOffset.UtcNow;
            run.Findings.AddRange(FindingFactory.CreateFindings(run, null, fatal: ex.Message));
            try
            {
                if (repository is not null)
                    await repository.SaveRunAsync(run, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                // 报告索引失败不删除已采集证据（设计文档 7.1）
            }
            run.State = RunState.Failed;
            return new DiagnosisOutcome { Run = run };
        }
    }

    private static async Task CheckpointAsync(
        NetFlow.Persistence.DiagnosisRepository? repository, DiagnosisRun run, CancellationToken ct)
    {
        if (repository is not null)
            await repository.SaveRunAsync(run, ct).ConfigureAwait(false);
    }

    private static string FileHashSha256(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fs));
    }
}

internal static class DiagnosisRunExtensions
{
    public static void AddSkippedStep(this DiagnosisRun run, ScenarioStep step, string reason)
    {
        var probeRun = new ProbeRun
        {
            RunId = run.Id,
            Parameters = new ProbeParameters
            {
                ProbeType = step.ProbeType,
                RequestedTarget = run.RequestedTarget,
                Extra = step.Parameters,
            },
            State = ProbeState.Completed,
            Transport = TransportOutcome.NotExecuted,
            Protocol = ProtocolOutcome.NotExecuted,
        };
        probeRun.AddObservation(Observation.Now(reason, step.Name));
        run.Probes.Add(probeRun);
    }

    public static void AddObservationToAll(this DiagnosisRun run, string text)
    {
        foreach (var p in run.Probes)
            p.AddObservation(Observation.Now(text, "任务级"));
    }
}
