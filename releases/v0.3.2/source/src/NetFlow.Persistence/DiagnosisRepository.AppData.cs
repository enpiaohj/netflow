using Microsoft.Data.Sqlite;

namespace NetFlow.Persistence;

/// <summary>端口包记录（entries 为文本格式，一行一项，如 <c>tcp/445 SMB</c>）。</summary>
public sealed record PortPackRecord(
    string Id, string Name, string Description, string Entries, DateTimeOffset UpdatedUtc);

/// <summary>
/// 应用数据（设置、端口包、最近输入）。与诊断记录共用同一连接和单写锁，
/// 保证 SQLite 单连接不被并发使用。
/// </summary>
public sealed partial class DiagnosisRepository
{
    // ---- 设置（键值）----

    public async Task<string?> GetSettingAsync(string key, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = "SELECT value FROM app_settings WHERE key = $k";
            cmd.Parameters.AddWithValue("$k", key);
            return await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task SetSettingAsync(string key, string value, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                INSERT INTO app_settings (key, value, updated_utc) VALUES ($k, $v, $t)
                ON CONFLICT(key) DO UPDATE SET value = $v, updated_utc = $t
                """;
            cmd.Parameters.AddWithValue("$k", key);
            cmd.Parameters.AddWithValue("$v", value);
            cmd.Parameters.AddWithValue("$t", ToIso(DateTimeOffset.UtcNow));
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // ---- 端口包 ----

    public async Task<IReadOnlyList<PortPackRecord>> ListPortPacksAsync(CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT id, name, description, entries, updated_utc FROM port_packs ORDER BY name COLLATE NOCASE
                """;
            var list = new List<PortPackRecord>();
            await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
            {
                list.Add(new PortPackRecord(
                    reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetString(3),
                    DateTimeOffset.Parse(reader.GetString(4))));
            }
            return list;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>按 Id 新增或覆盖端口包。名称与其他端口包重复时抛 <see cref="InvalidOperationException"/>。</summary>
    public async Task UpsertPortPackAsync(PortPackRecord pack, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                INSERT INTO port_packs (id, name, description, entries, updated_utc)
                VALUES ($id, $name, $desc, $entries, $t)
                ON CONFLICT(id) DO UPDATE SET
                  name = $name, description = $desc, entries = $entries, updated_utc = $t
                """;
            cmd.Parameters.AddWithValue("$id", pack.Id);
            cmd.Parameters.AddWithValue("$name", pack.Name);
            cmd.Parameters.AddWithValue("$desc", pack.Description);
            cmd.Parameters.AddWithValue("$entries", pack.Entries);
            cmd.Parameters.AddWithValue("$t", ToIso(pack.UpdatedUtc));
            try
            {
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // SQLITE_CONSTRAINT（name 唯一）
            {
                throw new InvalidOperationException($"已存在同名端口包：{pack.Name}", ex);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<bool> DeletePortPackAsync(string id, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = "DELETE FROM port_packs WHERE id = $id";
            cmd.Parameters.AddWithValue("$id", id);
            return await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false) > 0;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // ---- 最近输入 ----

    /// <summary>最近使用的输入值（最新在前）。</summary>
    public async Task<IReadOnlyList<string>> ListRecentAsync(
        string kind, int limit = 15, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = """
                SELECT value FROM recent_inputs WHERE kind = $k
                ORDER BY last_used_utc DESC, rowid DESC LIMIT $lim
                """;
            cmd.Parameters.AddWithValue("$k", kind);
            cmd.Parameters.AddWithValue("$lim", limit);
            var list = new List<string>();
            await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await reader.ReadAsync(ct).ConfigureAwait(false))
                list.Add(reader.GetString(0));
            return list;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>记录一次使用（已存在则刷新时间），并把该类别限制在 keep 条内。</summary>
    public async Task AddRecentAsync(
        string kind, string value, int keep = 15, CancellationToken ct = default,
        DateTimeOffset? usedUtc = null)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var tx = await _connection.BeginTransactionAsync(ct).ConfigureAwait(false);
            await ExecAsync(tx, ct, """
                INSERT INTO recent_inputs (kind, value, last_used_utc) VALUES ($k, $v, $t)
                ON CONFLICT(kind, value) DO UPDATE SET last_used_utc = $t
                """,
                ("$k", kind), ("$v", value), ("$t", ToIso(usedUtc ?? DateTimeOffset.UtcNow)));
            await ExecAsync(tx, ct, """
                DELETE FROM recent_inputs WHERE kind = $k AND value NOT IN (
                  SELECT value FROM recent_inputs WHERE kind = $k
                  ORDER BY last_used_utc DESC, rowid DESC LIMIT $keep)
                """,
                ("$k", kind), ("$keep", keep));
            await tx.CommitAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>清除最近输入；kind 为 null 清除全部类别。</summary>
    public async Task ClearRecentAsync(string? kind = null, CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var cmd = _connection.CreateCommand();
            cmd.CommandText = kind is null
                ? "DELETE FROM recent_inputs"
                : "DELETE FROM recent_inputs WHERE kind = $k";
            if (kind is not null) cmd.Parameters.AddWithValue("$k", kind);
            await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }
}
