using Microsoft.Data.Sqlite;
using NetFlow.Domain;

namespace NetFlow.Persistence;

/// <summary>
/// SQLite 诊断记录仓储。设计文档 7.2：
/// - 保存任务、探针、发现、证据元数据；原始证据独立文件不进 BLOB
/// - 迁移带版本号；受控单写队列；短事务
/// </summary>
public sealed class DiagnosisRepository : IAsyncDisposable
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly SqliteConnection _connection;

    public DiagnosisRepository(string databasePath)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(databasePath)!);
        _connection = new SqliteConnection(
            new SqliteConnectionStringBuilder
            {
                DataSource = databasePath,
                Mode = SqliteOpenMode.ReadWriteCreate,
                Pooling = false,
            }.ToString());
    }

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await _connection.OpenAsync(ct).ConfigureAwait(false);
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await MigrateAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // ---- 迁移 ----

    private async Task MigrateAsync(CancellationToken ct)
    {
        await using var tx = await _connection.BeginTransactionAsync(ct).ConfigureAwait(false);
        var cmd = _connection.CreateCommand();
        cmd.Transaction = (SqliteTransaction)tx;
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS schema_version (
              version INTEGER PRIMARY KEY,
              applied_utc TEXT NOT NULL);

            CREATE TABLE IF NOT EXISTS runs (
              id TEXT PRIMARY KEY,
              source_host TEXT NOT NULL,
              requested_target TEXT NOT NULL,
              resolved_addresses TEXT,
              adapter TEXT,
              scenario_id TEXT,
              scenario_name TEXT,
              scenario_version TEXT,
              scenario_json TEXT,
              start_utc TEXT,
              end_utc TEXT,
              app_version TEXT NOT NULL,
              elevated INTEGER NOT NULL DEFAULT 0,
              termination_reason TEXT);

            CREATE TABLE IF NOT EXISTS probes (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL REFERENCES runs(id),
              probe_type TEXT NOT NULL,
              state TEXT NOT NULL,
              transport TEXT NOT NULL,
              transport_detail TEXT,
              protocol TEXT NOT NULL,
              protocol_detail TEXT,
              source_address TEXT,
              error_code TEXT,
              parameters_json TEXT NOT NULL,
              start_utc TEXT, end_utc TEXT,
              resolved_addresses TEXT,
              stages_json TEXT,
              observations_json TEXT);

            CREATE TABLE IF NOT EXISTS findings (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL REFERENCES runs(id),
              severity TEXT NOT NULL,
              level TEXT NOT NULL,
              observed_facts TEXT NOT NULL,
              inference TEXT,
              limitations TEXT,
              next_steps TEXT,
              evidence_ids TEXT,
              rule_version TEXT NOT NULL);

            CREATE TABLE IF NOT EXISTS evidences (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL REFERENCES runs(id),
              probe_id TEXT,
              kind TEXT NOT NULL,
              side TEXT NOT NULL,
              captured_utc TEXT NOT NULL,
              artifact_path TEXT,
              summary TEXT,
              content_hash TEXT,
              redaction TEXT NOT NULL);

            CREATE TABLE IF NOT EXISTS artifacts (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL REFERENCES runs(id),
              format TEXT NOT NULL,
              absolute_path TEXT NOT NULL,
              size INTEGER NOT NULL,
              sha256 TEXT,
              retention TEXT NOT NULL);

            CREATE INDEX IF NOT EXISTS idx_probes_run ON probes(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_evidences_run ON evidences(run_id);
            CREATE INDEX IF NOT EXISTS idx_runs_start ON runs(start_utc);
            """;
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        await tx.CommitAsync(ct).ConfigureAwait(false);
    }

    // ---- 写入（单写队列 + 短事务）----

    public async Task SaveRunAsync(DiagnosisRun run, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var tx = await _connection.BeginTransactionAsync(ct).ConfigureAwait(false);

            await ExecAsync(tx, ct,
                """
                INSERT OR REPLACE INTO runs
                (id, source_host, requested_target, resolved_addresses, adapter,
                 scenario_id, scenario_name, scenario_version, scenario_json,
                 start_utc, end_utc, app_version, elevated, termination_reason)
                VALUES ($id,$sh,$rt,$ra,$ad,$sid,$sn,$sv,$sj,$su,$eu,$av,$el,$tr)
                """,
                ("$id", run.Id.ToString()),
                ("$sh", run.SourceHost),
                ("$rt", run.RequestedTarget),
                ("$ra", string.Join('|', run.ResolvedAddresses)),
                ("$ad", run.Adapter),
                ("$sid", run.Scenario?.TemplateId),
                ("$sn", run.Scenario?.TemplateName),
                ("$sv", run.Scenario?.TemplateVersion),
                ("$sj", run.Scenario is null ? null : System.Text.Json.JsonSerializer.Serialize(run.Scenario)),
                ("$su", ToIso(run.StartUtc)),
                ("$eu", ToIso(run.EndUtc)),
                ("$av", run.AppVersion),
                ("$el", run.Elevated ? 1 : 0),
                ("$tr", run.TerminationReason));

            foreach (var p in run.Probes)
            {
                await ExecAsync(tx, ct,
                    """
                    INSERT OR REPLACE INTO probes
                    (id, run_id, probe_type, state, transport, transport_detail, protocol,
                     protocol_detail, source_address, error_code, parameters_json,
                     start_utc, end_utc, resolved_addresses, stages_json, observations_json)
                    VALUES ($id,$rid,$pt,$st,$tr,$td,$pr,$pd,$sa,$ec,$pj,$su,$eu,$raddr,$stg,$obs)
                    """,
                    ("$id", p.Id.ToString()),
                    ("$rid", p.RunId.ToString()),
                    ("$pt", p.Parameters.ProbeType.ToString()),
                    ("$st", p.State.ToString()),
                    ("$tr", p.Transport.ToString()),
                    ("$td", p.TransportDetail),
                    ("$pr", p.Protocol.ToString()),
                    ("$pd", p.ProtocolDetail),
                    ("$sa", p.SourceAddress),
                    ("$ec", p.ErrorCode),
                    ("$pj", System.Text.Json.JsonSerializer.Serialize(p.Parameters)),
                    ("$su", ToIso(p.StartUtc)),
                    ("$eu", ToIso(p.EndUtc)),
                    ("$raddr", string.Join('|', p.ResolvedAddresses)),
                    ("$stg", System.Text.Json.JsonSerializer.Serialize(p.Stages)),
                    ("$obs", System.Text.Json.JsonSerializer.Serialize(p.Observations)));
            }

            foreach (var f in run.Findings)
            {
                await ExecAsync(tx, ct,
                    """
                    INSERT OR REPLACE INTO findings
                    (id, run_id, severity, level, observed_facts, inference, limitations,
                     next_steps, evidence_ids, rule_version)
                    VALUES ($id,$rid,$se,$le,$of,$inf,$lim,$ns,$eid,$rv)
                    """,
                    ("$id", f.Id.ToString()),
                    ("$rid", f.RunId.ToString()),
                    ("$se", f.Severity.ToString()),
                    ("$le", f.Level.ToString()),
                    ("$of", System.Text.Json.JsonSerializer.Serialize(f.ObservedFacts)),
                    ("$inf", f.Inference),
                    ("$lim", System.Text.Json.JsonSerializer.Serialize(f.Limitations)),
                    ("$ns", System.Text.Json.JsonSerializer.Serialize(f.NextSteps)),
                    ("$eid", System.Text.Json.JsonSerializer.Serialize(f.SupportingEvidenceIds.Select(e => e.ToString()))),
                    ("$rv", f.RuleVersion));
            }

            foreach (var e in run.Evidences)
            {
                await ExecAsync(tx, ct,
                    """
                    INSERT OR REPLACE INTO evidences
                    (id, run_id, probe_id, kind, side, captured_utc, artifact_path,
                     summary, content_hash, redaction)
                    VALUES ($id,$rid,$pid,$kind,$side,$cap,$path,$sum,$hash,$red)
                    """,
                    ("$id", e.Id.ToString()),
                    ("$rid", e.RunId.ToString()),
                    ("$pid", e.ProbeId?.ToString()),
                    ("$kind", e.Kind.ToString()),
                    ("$side", e.Side.ToString()),
                    ("$cap", ToIso(e.CapturedUtc)),
                    ("$path", e.ArtifactPath),
                    ("$sum", e.Summary),
                    ("$hash", e.ContentHash),
                    ("$red", e.Redaction.ToString()));
            }

            foreach (var a in run.Artifacts)
            {
                await ExecAsync(tx, ct,
                    """
                    INSERT OR REPLACE INTO artifacts
                    (id, run_id, format, absolute_path, size, sha256, retention)
                    VALUES ($id,$rid,$fmt,$path,$size,$hash,$ret)
                    """,
                    ("$id", a.Id.ToString()),
                    ("$rid", a.RunId.ToString()),
                    ("$fmt", a.Format),
                    ("$path", a.AbsolutePath),
                    ("$size", a.Size),
                    ("$hash", a.Sha256),
                    ("$ret", a.Retention.ToString()));
            }

            await tx.CommitAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // ---- 查询 ----

    public async Task<IReadOnlyList<(string Id, string Target, DateTimeOffset? Start, string? ScenarioName)>>
        ListRunsAsync(int limit = 200, CancellationToken ct = default)
    {
        var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            SELECT id, requested_target, start_utc,
                   COALESCE(scenario_name,'') FROM runs
            ORDER BY start_utc DESC LIMIT $lim
            """;
        cmd.Parameters.AddWithValue("$lim", limit);
        var result = new List<(string, string, DateTimeOffset?, string?)>();
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            result.Add((
                reader.GetString(0),
                reader.GetString(1),
                reader.IsDBNull(2) ? null : DateTimeOffset.Parse(reader.GetString(2)),
                reader.IsDBNull(3) ? null : reader.GetString(3)));
        }
        return result;
    }

    /// <summary>留存清理：删除超期的 runs 及关联行。返回受影响 run 数。</summary>
    public async Task<int> PurgeOlderThanAsync(
        DateTimeOffset cutoffUtc, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var tx = await _connection.BeginTransactionAsync(ct).ConfigureAwait(false);
            var ids = new List<string>();
            var select = _connection.CreateCommand();
            select.Transaction = (SqliteTransaction)tx;
            select.CommandText = "SELECT id FROM runs WHERE start_utc < $cut";
            select.Parameters.AddWithValue("$cut", ToIso(cutoffUtc));
            await using (var reader = await select.ExecuteReaderAsync(ct).ConfigureAwait(false))
            {
                while (await reader.ReadAsync(ct).ConfigureAwait(false))
                    ids.Add(reader.GetString(0));
            }

            foreach (var table in new[] { "probes", "findings", "evidences", "artifacts", "runs" })
            {
                var del = _connection.CreateCommand();
                del.Transaction = (SqliteTransaction)tx;
                del.CommandText = $"DELETE FROM {table} WHERE run_id IN (SELECT id FROM runs WHERE start_utc < $cut)";
                del.Parameters.AddWithValue("$cut", ToIso(cutoffUtc));
                await del.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
            await tx.CommitAsync(ct).ConfigureAwait(false);
            return ids.Count;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // ---- 工具 ----

    private async Task ExecAsync(
        System.Data.Common.DbTransaction tx, CancellationToken ct, string sql,
        params (string Name, object? Value)[] parameters)
    {
        await using var cmd = _connection.CreateCommand();
        cmd.Transaction = (SqliteTransaction)tx;
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static string ToIso(DateTimeOffset? t) =>
        t?.UtcDateTime.ToString("o") ?? "";

    public async ValueTask DisposeAsync()
    {
        await _connection.DisposeAsync().ConfigureAwait(false);
        _writeLock.Dispose();
    }
}
