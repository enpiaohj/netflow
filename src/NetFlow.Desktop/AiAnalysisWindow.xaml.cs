using System.Windows;
using NetFlow.Application.Ai;
using NetFlow.Desktop.Pages;
using NetFlow.Desktop.Services;

namespace NetFlow.Desktop;

/// <summary>
/// AI 深入分析窗口：展示将发送的（已脱敏）内容 → 用户确认 → 调用 DeepSeek → 展示结果。
/// 设置了“发送前确认”时不会自动发送；结果中被占位符替换的地址在本地还原。
/// </summary>
public partial class AiAnalysisWindow : Window
{
    private readonly AiPreparedContext _prepared;
    private CancellationTokenSource? _cts;

    private AiAnalysisWindow(string title, AiPreparedContext prepared, bool confirmFirst)
    {
        InitializeComponent();
        _prepared = prepared;

        var ai = AppServices.Instance.Settings.Current.Ai;
        TitleText.Text = $"AI 深入分析：{title}";
        ProviderText.Text = $"服务商 {ai.Provider} · 模型 {ai.Model}" +
            (ai.MaskAddresses ? " · IPv4 地址已替换为占位符" : "");
        ContextBox.Text = prepared.Text;
        ContextHeader.Text = $"发送内容预览（已脱敏，共 {prepared.Text.Length} 字符）";
        ContextExpander.IsExpanded = confirmFirst;
        StartButton.Content = confirmFirst ? "确认发送并分析" : "开始分析";

        if (!confirmFirst)
            Loaded += (_, _) => Start_Click(this, new RoutedEventArgs());
    }

    /// <summary>
    /// 打开分析窗口。未启用/未配置 Key 时提示并引导去设置页，不发送任何内容。
    /// </summary>
    public static void Open(string title, string context)
    {
        var services = AppServices.Instance;
        if (!services.Ai.IsReady(out var reason))
        {
            var go = MessageBox.Show(
                $"{reason}\n\n是否打开“设置”？", "NetFlow AI 分析",
                MessageBoxButton.YesNo, MessageBoxImage.Information);
            if (go == MessageBoxResult.Yes) NavigationState.Raise("settings");
            return;
        }

        var prepared = services.Ai.Prepare(context);
        var window = new AiAnalysisWindow(title, prepared, services.Settings.Current.Ai.ConfirmBeforeSend)
        {
            Owner = System.Windows.Application.Current.MainWindow,
        };
        window.Show();
    }

    private async void Start_Click(object sender, RoutedEventArgs e)
    {
        StartButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        CopyButton.IsEnabled = false;
        ResultBox.Clear();
        StatusText.Text = "正在分析，通常需要 30–120 秒…";
        _cts = new CancellationTokenSource();

        AiChatResult result;
        try
        {
            result = await AppServices.Instance.Ai
                .AnalyzeAsync(_prepared, QuestionBox.Text, _cts.Token).ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            // 服务内部已把已知错误转成结果；这里兜底未预期异常，只显示类型与消息（不含请求内容）
            result = AiChatResult.Fail($"分析失败：{ex.Message}");
        }

        CancelButton.IsEnabled = false;
        StartButton.IsEnabled = true;
        StartButton.Content = "重新分析";

        if (!result.Success)
        {
            StatusText.Text = "分析失败";
            ResultBox.Text = result.Error ?? "未知错误";
            return;
        }

        var usage = result.PromptTokens is { } p && result.CompletionTokens is { } c
            ? $"｜用量：输入 {p} + 输出 {c} tokens" : "";
        StatusText.Text = result.Truncated
            ? $"结果已被截断{usage}。请在“设置”中降低推理强度，或缩小分析范围后重试。"
            : $"分析完成{usage}";
        ResultBox.Text = result.Reasoning is { Length: > 0 } reasoning
            ? $"{result.Content}\n\n—— 推理过程 ——\n{reasoning}"
            : result.Content;
        CopyButton.IsEnabled = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _cts?.Cancel();

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(ResultBox.Text);
            StatusText.Text = "已复制到剪贴板";
        }
        catch (System.Runtime.InteropServices.COMException)
        {
            StatusText.Text = "无法复制：剪贴板正被其他程序使用，请重试。";
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _cts?.Cancel();
        _cts?.Dispose();
        base.OnClosed(e);
    }
}
