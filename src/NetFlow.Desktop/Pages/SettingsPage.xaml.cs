using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using NetFlow.Application;
using NetFlow.Capture;
using NetFlow.Desktop.Services;
using NetFlow.Domain;

namespace NetFlow.Desktop.Pages;

public partial class SettingsPage : UserControl
{
    /// <summary>加载设置到控件期间置位，避免控件事件反向触发保存。</summary>
    private bool _loading = true;

    public SettingsPage()
    {
        InitializeComponent();
        FillChoices();
        LoadFromSettings();
        _loading = false;

        Loaded += async (_, _) =>
        {
            var services = AppServices.Instance;
            ElevatedText.Text = NetworkInterfaceHelper.IsElevated()
                ? "当前以管理员身份运行，可直接抓包。"
                : "当前以标准用户身份运行。开始抓包时将请求管理员权限；若拒绝，则无法抓包，其他检测不受影响。";
            StorageText.Text =
                $"数据库：{services.DatabasePath}（{(services.PersistenceReady ? "可用" : "不可用")}）\n" +
                $"证据文件夹：{services.EvidenceRoot}\n" +
                "设置、端口包、输入历史和诊断记录均保存在上述 SQLite 数据库中。";
            AboutVersionText.Text = $"v{NetFlowInfo.Version}";
            AboutPrivilegeText.Text = NetworkInterfaceHelper.IsElevated() ? "已使用管理员权限" : "标准用户权限";
            DeveloperRun.Text = NetFlowInfo.Developer;
            DeveloperLink.NavigateUri = new Uri(NetFlowInfo.DeveloperUrl);
            RepositoryRun.Text = NetFlowInfo.RepositoryUrl;
            RepositoryLink.NavigateUri = new Uri(NetFlowInfo.RepositoryUrl);
            LicenseText.Text = NetFlowInfo.License;
            AboutText.Text =
                $"数据库：{services.DatabasePath}\n" +
                $"证据文件夹：{services.EvidenceRoot}\n" +
                $"数据库状态：{(services.PersistenceReady ? "正常" : $"不可用（{services.PersistenceError}）。设置和端口包仅在本次运行期间有效")}";
            await DetectPktmonAsync().ConfigureAwait(true);
            await DetectTsharkAsync().ConfigureAwait(true);
        };
    }

    private void Link_RequestNavigate(object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        e.Handled = true;
        try
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception)
        {
            MessageBox.Show("无法打开链接，请检查系统默认浏览器设置。", "NetFlow",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static void Fill(ComboBox combo, params string[] values)
    {
        foreach (var v in values) combo.Items.Add(v);
    }

    private void FillChoices()
    {
        Fill(DefaultTimeoutInput, "1", "2", "3", "5", "10", "30");
        Fill(DefaultConcurrencyInput, "1", "2", "4", "8", "16", "32");
        Fill(CaptureDurationInput, "10", "30", "60", "120", "300", "600", "1800", "3600");
        Fill(CaptureSnapInput, "0", "64", "128", "256", "512", "1514");
        Fill(RetentionInput, "7", "14", "30", "60", "90", "180", "365");
        Fill(AiTimeoutInput, "30", "60", "120", "180", "300");
    }

    private void LoadFromSettings()
    {
        var s = AppServices.Instance.Settings.Current;
        DefaultTimeoutInput.Text = s.DefaultTimeoutSeconds.ToString("0.##");
        DefaultConcurrencyInput.Text = s.BatchConcurrency.ToString();
        CaptureModeInput.SelectedIndex = s.CaptureMode == "live" ? 1 : 0;
        CaptureDurationInput.Text = s.CaptureDurationSeconds.ToString();
        CaptureSnapInput.Text = s.CaptureSnapBytes.ToString();
        RedactionToggle.IsChecked = s.RedactionEnabled;
        RetentionInput.Text = s.RetentionDays.ToString();

        AiEnabledToggle.IsChecked = s.Ai.Enabled;
        AiBaseUrlInput.Text = s.Ai.BaseUrl;
        AiModelInput.Text = s.Ai.Model;
        AiTimeoutInput.Text = s.Ai.TimeoutSeconds.ToString();
        AiEffortInput.SelectedIndex = EffortIndex(s.Ai.ReasoningEffort);
        AiConfirmToggle.IsChecked = s.Ai.ConfirmBeforeSend;
        AiMaskToggle.IsChecked = s.Ai.MaskAddresses;
        RefreshKeyStatus();
    }

    /// <summary>任一设置控件变化 → 读取全部控件值 → 校验修正后持久化。</summary>
    private void Setting_Changed(object sender, RoutedEventArgs e)
    {
        if (_loading || !IsLoaded) return;

        static bool Int(string text, out int value) => int.TryParse(text.Trim(), out value);
        var store = AppServices.Instance.Settings;
        var current = store.Current;

        _ = store.UpdateAsync(s => s with
        {
            DefaultTimeoutSeconds = double.TryParse(DefaultTimeoutInput.Text, out var t) ? t : s.DefaultTimeoutSeconds,
            BatchConcurrency = Int(DefaultConcurrencyInput.Text, out var c) ? c : s.BatchConcurrency,
            CaptureMode = CaptureModeInput.SelectedIndex == 1 ? "live" : "record",
            CaptureDurationSeconds = Int(CaptureDurationInput.Text, out var d) ? d : s.CaptureDurationSeconds,
            CaptureSnapBytes = Int(CaptureSnapInput.Text, out var sn) ? sn : s.CaptureSnapBytes,
            RedactionEnabled = RedactionToggle.IsChecked == true,
            RetentionDays = Int(RetentionInput.Text, out var r) ? r : s.RetentionDays,
            Ai = s.Ai with
            {
                Enabled = AiEnabledToggle.IsChecked == true,
                BaseUrl = string.IsNullOrWhiteSpace(AiBaseUrlInput.Text) ? s.Ai.BaseUrl : AiBaseUrlInput.Text.Trim(),
                Model = string.IsNullOrWhiteSpace(AiModelInput.Text) ? s.Ai.Model : AiModelInput.Text.Trim(),
                TimeoutSeconds = Int(AiTimeoutInput.Text, out var at) ? at : s.Ai.TimeoutSeconds,
                ReasoningEffort = EffortValue(AiEffortInput.SelectedIndex),
                ConfirmBeforeSend = AiConfirmToggle.IsChecked == true,
                MaskAddresses = AiMaskToggle.IsChecked == true,
            },
        });

        // 越界值被修正后回显（如并发 999 → 32），让界面与实际生效值一致
        var applied = store.Current;
        if (applied != current)
        {
            _loading = true;
            try { RefreshNumbers(applied); }
            finally { _loading = false; }
        }
    }

    private static int EffortIndex(string effort) => effort switch
    {
        "low" => 0,
        "high" => 1,
        "max" => 2,
        _ => 3,
    };

    private static string EffortValue(int index) => index switch
    {
        1 => "high",
        2 => "max",
        3 => "",
        _ => "low",
    };

    private void RefreshNumbers(AppSettings s)
    {
        DefaultTimeoutInput.Text = s.DefaultTimeoutSeconds.ToString("0.##");
        DefaultConcurrencyInput.Text = s.BatchConcurrency.ToString();
        CaptureDurationInput.Text = s.CaptureDurationSeconds.ToString();
        CaptureSnapInput.Text = s.CaptureSnapBytes.ToString();
        RetentionInput.Text = s.RetentionDays.ToString();
        AiTimeoutInput.Text = s.Ai.TimeoutSeconds.ToString();
    }

    // ---- 常规 ----

    private void ResetSource_Click(object sender, RoutedEventArgs e) => SourceSelection.RequestReset();

    // ---- 抓包引擎 ----

    private async Task DetectPktmonAsync()
    {
        PktmonText.Text = "正在检测…";
        var cap = await PktmonCaptureController.DetectCapabilityAsync(CancellationToken.None)
            .ConfigureAwait(true);
        PktmonText.Text = cap.Available
            ? $"已检测到 Windows Pktmon（{cap.Version}）。"
            : $"无法使用 Pktmon：{cap.Error}。抓包不可用，仍可进行网络测试和导入分析。";
    }

    private async Task DetectTsharkAsync()
    {
        TsharkText.Text = "正在检测 TShark…";
        var cap = await TsharkAdapter.DetectAsync(CancellationToken.None).ConfigureAwait(true);
        TsharkText.Text = cap.Available
            ? $"TShark {cap.Version}（{cap.Path}）。用于深入解析 PCAPNG 文件，非默认抓包引擎。"
            : $"未检测到 TShark（可选组件）。{cap.Error}";
    }

    private async void Detect_Click(object sender, RoutedEventArgs e) =>
        await DetectPktmonAsync().ConfigureAwait(true);

    private async void DetectTshark_Click(object sender, RoutedEventArgs e) =>
        await DetectTsharkAsync().ConfigureAwait(true);

    // ---- 数据与隐私 ----

    private void OpenDataFolder_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = Path.GetDirectoryName(AppServices.Instance.DatabasePath)!,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            PurgeStatus.Text = $"无法打开数据文件夹：{ex.Message}";
        }
    }

    /// <summary>证据文件夹名为 32 位十六进制的任务 ID：只清理这类目录，不碰其他任何文件。</summary>
    private static readonly Regex RunDirName = new("^[0-9a-f]{32}$", RegexOptions.Compiled);

    private async void Purge_Click(object sender, RoutedEventArgs e)
    {
        var services = AppServices.Instance;
        var days = services.Settings.Current.RetentionDays;
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days);

        var confirm = MessageBox.Show(
            $"将删除 {days} 天前（{cutoff.LocalDateTime:yyyy-MM-dd} 之前）的诊断记录及证据文件夹（报告、抓包文件）。\n此操作无法撤销，是否继续？",
            "NetFlow 清理确认", MessageBoxButton.OKCancel, MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.OK) return;

        try
        {
            var runs = 0;
            if (services.PersistenceReady && services.Repository is { } repo)
                runs = await repo.PurgeOlderThanAsync(cutoff).ConfigureAwait(true);

            var dirs = 0;
            await Task.Run(() =>
            {
                foreach (var dir in Directory.EnumerateDirectories(services.EvidenceRoot))
                {
                    if (!RunDirName.IsMatch(Path.GetFileName(dir))) continue;
                    if (Directory.GetLastWriteTimeUtc(dir) >= cutoff.UtcDateTime) continue;
                    try
                    {
                        Directory.Delete(dir, recursive: true);
                        dirs++;
                    }
                    catch (IOException ex)
                    {
                        AppLog.Warn($"清理证据文件夹失败（已跳过）：{dir}：{ex.Message}");
                    }
                }
            }).ConfigureAwait(true);

            PurgeStatus.Text = $"已清理 {runs} 条诊断记录和 {dirs} 个证据文件夹。";
        }
        catch (Exception ex)
        {
            AppLog.Error("留存清理失败", ex);
            PurgeStatus.Text = $"无法清理：{ex.Message}";
        }
    }

    private void ClearRecent_Click(object sender, RoutedEventArgs e)
    {
        UiState.ClearRecent();
        ClearRecentStatus.Text = "已清除输入历史。";
    }

    // ---- AI ----

    private void RefreshKeyStatus()
    {
        var store = AppServices.Instance.Settings;
        ApiKeyStatus.Text = store.HasApiKey
            ? store.TryGetApiKey() is null
                ? "无法解密已保存的密钥（可能由其他 Windows 账户或计算机保存），请重新输入。"
                : $"已保存密钥：{store.MaskedApiKey()}"
            : "尚未保存 API Key。";
    }

    private async void SaveKey_Click(object sender, RoutedEventArgs e)
    {
        var key = ApiKeyBox.Password.Trim();
        if (key.Length < 8)
        {
            ApiKeyStatus.Text = "API Key 长度不足，请检查后重新输入。";
            return;
        }
        await AppServices.Instance.Settings.SetApiKeyAsync(key).ConfigureAwait(true);
        ApiKeyBox.Clear();
        RefreshKeyStatus();
        AiTestResult.Text = "";
    }

    private async void ClearKey_Click(object sender, RoutedEventArgs e)
    {
        await AppServices.Instance.Settings.SetApiKeyAsync(null).ConfigureAwait(true);
        ApiKeyBox.Clear();
        RefreshKeyStatus();
    }

    /// <summary>读取官方模型列表填入下拉；成功后若当前模型不在列表中给出提示。</summary>
    private async void ListModels_Click(object sender, RoutedEventArgs e)
    {
        AiTestResult.Foreground = (System.Windows.Media.Brush)FindResource("PrimaryBrush");
        AiTestResult.Text = "正在获取模型列表…";
        var (models, error) = await AppServices.Instance.Ai.ListModelsAsync().ConfigureAwait(true);
        if (error is not null)
        {
            AiTestResult.Foreground = (System.Windows.Media.Brush)FindResource("StatusFail");
            AiTestResult.Text = error;
            return;
        }

        var current = AiModelInput.Text;
        _loading = true;
        try
        {
            AiModelInput.Items.Clear();
            foreach (var m in models) AiModelInput.Items.Add(m);
            AiModelInput.Text = current;
        }
        finally
        {
            _loading = false;
        }
        AiTestResult.Text = models.Contains(current)
            ? $"可用模型：{string.Join("、", models)}"
            : $"可用模型：{string.Join("、", models)}。当前模型“{current}”不在列表中，请重新选择。";
    }

    private async void TestAi_Click(object sender, RoutedEventArgs e)
    {
        AiTestResult.Foreground = (System.Windows.Media.Brush)FindResource("PrimaryBrush");
        AiTestResult.Text = "正在测试…";
        try
        {
            var result = await AppServices.Instance.Ai.TestConnectionAsync().ConfigureAwait(true);
            if (result.Success)
            {
                AiTestResult.Text = $"连接成功，模型：{AppServices.Instance.Settings.Current.Ai.Model}。";
            }
            else
            {
                AiTestResult.Foreground = (System.Windows.Media.Brush)FindResource("StatusFail");
                AiTestResult.Text = result.Error ?? "连接失败";
            }
        }
        catch (Exception ex)
        {
            AiTestResult.Foreground = (System.Windows.Media.Brush)FindResource("StatusFail");
            AiTestResult.Text = $"无法测试：{ex.Message}";
        }
    }
}
