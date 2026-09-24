using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Application;
using NetFlow.Application.Ai;
using NetFlow.Desktop.Services;
using System.IO;
using NetFlow.Domain;

namespace NetFlow.Desktop.Pages;

public partial class ScenarioPage : UserControl
{
    public ObservableCollection<ScenarioStepRow> Rows { get; } = [];

    private DiagnosisRun? _lastRun;
    private CancellationTokenSource? _cts;

    public ScenarioPage()
    {
        InitializeComponent();
        ResultGrid.ItemsSource = Rows;
        UiState.Bind(TargetInput, "target");
        UiState.Bind(DomainInput, "domain");
        ReloadTemplates();
        TemplateList.SelectionChanged += (_, _) => UpdateTemplateInfo();
        UpdateTemplateInfo();
        Loaded += (_, _) =>
        {
            if (NavigationState.PendingScenarioRun is { } rerun)
            {
                NavigationState.PendingScenarioRun = null;
                TargetInput.Text = rerun.Target;
                var items = (List<TemplateItem>)TemplateList.ItemsSource;
                var idx = items.FindIndex(i => i.Id == rerun.ScenarioId);
                if (idx >= 0) TemplateList.SelectedIndex = idx;
            }
        };
    }

    private void ReloadTemplates()
    {
        var items = new List<TemplateItem>();
        // 列表项只显示名称（版本号会让名称过长），版本/来源/方向显示在列表下方的信息行
        foreach (var t in BuiltinTemplates.All)
            items.Add(new TemplateItem(t.Id, t.Name, t.Direction, null, $"{t.Version}",
                t.Steps.Any(st => st.ProbeType == ProbeType.SqlServer)));
        foreach (var u in AppServices.Instance.UserTemplates.All)
            items.Add(new TemplateItem(u.Id, $"{u.Name}（自定义）", u.Direction, u.Id, $"{u.Version}",
                u.Steps.Any(st => st.ProbeType == ProbeType.SqlServer)));
        TemplateList.ItemsSource = items;
        if (TemplateList.SelectedIndex < 0) TemplateList.SelectedIndex = 0;
    }

    private void SaveTemplate_Click(object sender, RoutedEventArgs e)
    {
        if (TemplateList.SelectedItem is not TemplateItem item) return;
        if (item.UserFileId is not null)
        {
            MessageBox.Show("这已是自定义模板。当前请直接编辑 user-templates.json，后续版本将提供编辑器。", "NetFlow");
            return;
        }
        var source = BuiltinTemplates.Find(item.Id);
        if (source is null) return;

        var name = source.Name + "（副本）";
        AppServices.Instance.UserTemplates.CreateFromBuiltin(source, name);
        ReloadTemplates();
        AppServices.Instance.PublishStatus($"已创建自定义模板“{name}”。内置模板为只读，修改副本不会影响历史报告。");
    }

    private sealed record TemplateItem(
        string Id, string Name, string Direction, string? UserFileId, string Version, bool UsesSql)
    {
        // 自动化名称/读屏取 ToString，避免显示 record 默认文本
        public override string ToString() => Name;
    }

    /// <summary>选中模板的来源、版本与方向。</summary>
    private void UpdateTemplateInfo()
    {
        // SQL Server 场景显示“实例/端口”输入（此类场景用不到域），其余显示“域”
        var usesSql = TemplateList.SelectedItem is TemplateItem { UsesSql: true };
        SqlPanel.Visibility = usesSql ? Visibility.Visible : Visibility.Collapsed;
        DomainPanel.Visibility = usesSql ? Visibility.Collapsed : Visibility.Visible;

        TemplateInfo.Text = TemplateList.SelectedItem is TemplateItem t
            ? $"{(t.UserFileId is null ? "内置模板" : "自定义模板")} v{t.Version}\n方向：{t.Direction}"
            : "";
    }

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        if (TemplateList.SelectedItem is not TemplateItem item)
            return;

        var target = TargetInput.Text.Trim();
        var domain = DomainInput.Text.Trim();
        if (target.Length == 0)
        {
            ProgressText.Text = "请输入目标主机";
            TargetInput.Focus();
            return;
        }

        // 源网卡：目标为 IPv6 字面量时取 IPv6 地址，其余按 IPv4；编排器会优先选择同协议族的解析结果
        var family = System.Net.IPAddress.TryParse(target, out var literal)
            ? literal.AddressFamily
            : System.Net.Sockets.AddressFamily.InterNetwork;
        var (source, sourceError) = SourceSelection.Resolve(family);
        if (sourceError is not null)
        {
            ProgressText.Text = sourceError;
            return;
        }

        var sqlTarget = item.UsesSql
            ? SqlTargetParser.Parse(SqlInput.Text)
            : new SqlTargetParser.Result(null, null, null);
        if (sqlTarget.Error is not null)
        {
            ProgressText.Text = sqlTarget.Error;
            SqlInput.Focus();
            return;
        }

        UiState.Remember(TargetInput, "target");
        if (domain.Length > 0) UiState.Remember(DomainInput, "domain");
        AiButton.IsEnabled = false;

        RunButton.IsEnabled = false;
        StopButton.IsEnabled = true;
        ExportButton.IsEnabled = false;
        Rows.Clear();
        EvidenceBox.Clear();
        ProgressText.Text = "正在准备…";
        _cts = new CancellationTokenSource();
        ActivityState.Begin(this, "scenario", $"场景诊断 {target}");

        var request = new DiagnosisRequest
        {
            RequestedTarget = target,
            ScenarioId = item.Id,
            DomainName = domain.Length > 0 ? domain : null,
            SourceAddress = source,
            SqlInstanceName = sqlTarget.InstanceName,
            SqlFixedPort = sqlTarget.Port,
            Timeout = TimeSpan.FromSeconds(3),
        };

        // 用户自定义模板：以固化快照参与执行（版本进入报告）
        if (item.UserFileId is { } fileId)
        {
            var file = AppServices.Instance.UserTemplates.All
                .FirstOrDefault(u => u.Id == fileId);
            if (file is not null)
                request = request with { CustomTemplate = AppServices.Instance.UserTemplates.ToTemplate(file) };
        }

        var services = AppServices.Instance;
        var capture = CaptureToggle.IsChecked == true
            ? (ITaskCaptureHook)services.CaptureController
            : null;
        _lastRun = null;

        DiagnosisOutcome outcome;
        try
        {
            outcome = await services.Orchestrator.ExecuteAsync(
                request,
                services.PersistenceReady ? services.Repository : null,
                capture, _cts.Token).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            ProgressText.Text = "已取消";
            return;
        }
        catch (Exception ex)
        {
            AppLog.Error("场景诊断执行异常", ex);
            ProgressText.Text = $"执行失败：{ex.Message}";
            return;
        }
        finally
        {
            // 取消/异常路径在此统一恢复按钮状态（成功路径下方会再更新进度文本）
            ActivityState.End(this);
            RunButton.IsEnabled = true;
            StopButton.IsEnabled = false;
            ExportButton.IsEnabled = true;
        }
        _lastRun = outcome.Run;
        RenderRun(_lastRun);

        // 报告导出到证据文件夹
        var artifacts = services.ReportExport.ExportAll(_lastRun, services.EvidenceRoot);
        foreach (var a in artifacts)
            _lastRun.Artifacts.Add(a);
        await services.SaveRunSafeAsync(_lastRun).ConfigureAwait(true);

        ProgressText.Text = _lastRun.TerminationReason is null
            ? $"已完成：{_lastRun.Probes.Count} 项检查"
            : $"已终止：{_lastRun.TerminationReason}";
    }

    private async void Stop_Click(object sender, RoutedEventArgs e)
    {
        _cts?.Cancel();
        ProgressText.Text = "正在取消…";
        await Task.CompletedTask.ConfigureAwait(true);
    }

    private void TargetInput_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Enter)
        {
            e.Handled = true;
            Run_Click(sender, e);
        }
    }

    private void RenderRun(DiagnosisRun run)
    {
        ResultTitle.Text = run.Scenario is null
            ? "诊断概览"
            : $"{run.Scenario.TemplateName}（{run.Scenario.Direction}）";

        int no = 1;
        int pass = 0, warn = 0, unconfirmed = 0, fail = 0;
        EventTimeline.Items.Clear();
        foreach (var p in run.Probes)
        {
            var level = UiText.LevelOfRun(p);
            switch (level)
            {
                case ConclusionLevel.Pass: pass++; break;
                case ConclusionLevel.Warning: warn++; break;
                case ConclusionLevel.Unconfirmed: unconfirmed++; break;
                case ConclusionLevel.Fail: fail++; break;
            }
            Rows.Add(new ScenarioStepRow
            {
                No = no,
                Name = p.Parameters.Extra.TryGetValue("__stepName", out var n) ? n : UiText.ProbeName(p.Parameters.ProbeType),
                Level = UiText.Level(level),
                LevelBrush = UiText.LevelBrush(level),
                Transport = UiText.Transport(p.Transport),
                Protocol = UiText.Protocol(p.Protocol),
                Elapsed = UiText.Elapsed(p.Elapsed),
            });
            foreach (var obs in p.Observations.Take(2))
            {
                EventTimeline.Items.Add(new TimelineItem
                {
                    Time = obs.ObservedUtc.LocalDateTime.ToString("HH:mm:ss.fff"),
                    Text = "[" + UiText.ProbeName(p.Parameters.ProbeType) + "] " + obs.Text,
                    DotBrush = UiText.LevelBrush(level),
                });
            }
            no++;
        }

        AiButton.IsEnabled = true;

        // KPI 统计卡 + 汇总标题（概念图 01）
        StatCards.Visibility = Visibility.Visible;
        KpiPass.Text = pass.ToString();
        KpiWarn.Text = warn.ToString();
        KpiUnconfirmed.Text = unconfirmed.ToString();
        KpiFail.Text = fail.ToString();
        ResultTitle.Text += $"　共 {run.Probes.Count} 项检查";

        EvidenceBox.AppendText($"任务 ID：{run.Id}\n");
        EvidenceBox.AppendText($"解析地址：{string.Join("、", run.ResolvedAddresses)}\n");
        EvidenceBox.AppendText($"终止原因：{run.TerminationReason ?? "正常"}\n\n");
        foreach (var f in run.Findings)
        {
            EvidenceBox.AppendText($"[{f.Severity}] {LevelText(f.Level)}\n");
            foreach (var fact in f.ObservedFacts)
                EvidenceBox.AppendText($"  事实：{fact}\n");
            if (f.Inference is not null)
                EvidenceBox.AppendText($"  推断：{f.Inference}\n");
            foreach (var lim in f.Limitations)
                EvidenceBox.AppendText($"  限制：{lim}\n");
            foreach (var step in f.NextSteps)
                EvidenceBox.AppendText($"  下一步：{step}\n");
            EvidenceBox.AppendText("\n");
        }
    }

    private void Ai_Click(object sender, RoutedEventArgs e)
    {
        if (_lastRun is null) return;
        AiAnalysisWindow.Open(
            $"场景诊断 {_lastRun.RequestedTarget}", AiPromptBuilder.BuildRunContext(_lastRun));
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        if (_lastRun is null) return;
        var html = _lastRun.Artifacts.FirstOrDefault(a => a.Format == "html");
        if (html is null || !File.Exists(html.AbsolutePath))
        {
            MessageBox.Show("报告尚未生成。", "NetFlow");
            return;
        }
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = html.AbsolutePath,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show($"无法打开报告：{ex.Message}", "NetFlow");
        }
    }

    private static string LevelText(ConclusionLevel level) => level switch
    {
        ConclusionLevel.Pass => "通过",
        ConclusionLevel.Warning => "警告",
        ConclusionLevel.Fail => "失败",
        ConclusionLevel.Unconfirmed => "未确认",
        ConclusionLevel.NotChecked => "未检查",
        ConclusionLevel.Skipped => "跳过",
        ConclusionLevel.Canceled => "已取消",
        _ => level.ToString(),
    };
}

public record ScenarioStepRow
{
    public required int No { get; init; }
    public required string Name { get; init; }
    public required string Level { get; init; }
    public required System.Windows.Media.Brush LevelBrush { get; init; }
    public required string Transport { get; init; }
    public required string Protocol { get; init; }
    public required string Elapsed { get; init; }
}

public record TimelineItem
{
    public required string Time { get; init; }
    public required string Text { get; init; }
    public required System.Windows.Media.Brush DotBrush { get; init; }
}
