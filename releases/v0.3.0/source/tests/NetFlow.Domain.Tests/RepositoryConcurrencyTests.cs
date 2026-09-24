using NetFlow.Domain;
using NetFlow.Persistence;
using Xunit;

namespace NetFlow.Domain.Tests;

/// <summary>仓储并发稳定性：读写全部串行化后，并发保存不产生连接冲突。</summary>
public class RepositoryConcurrencyTests
{
    [Fact]
    public async Task ParallelSaveAndList_DoNotThrow()
    {
        var db = Path.Combine(Path.GetTempPath(), $"nf-conc-{Guid.NewGuid():N}.db");
        try
        {
            await using var repository = new DiagnosisRepository(db);
            await repository.InitializeAsync();

            var runs = Enumerable.Range(0, 8).Select(_ => new DiagnosisRun
            {
                SourceHost = "test",
                RequestedTarget = "192.168.10.11",
                AppVersion = NetFlowInfo.Version,
            }).ToList();

            // 并发写 + 并发读（修复前：单连接并发使用会抛 "connection is in use"）
            var tasks = runs.Select(r => repository.SaveRunAsync(r)).ToList();
            for (int i = 0; i < 5; i++)
            {
                tasks.Add(Task.Run(async () =>
                {
                    await Task.Delay(10);
                    await repository.ListRunsAsync(10);
                }));
            }
            await Task.WhenAll(tasks);
        }
        finally
        {
            if (File.Exists(db)) File.Delete(db);
        }
    }
}
