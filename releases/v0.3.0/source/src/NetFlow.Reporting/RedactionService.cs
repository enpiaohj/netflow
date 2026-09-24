using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NetFlow.Reporting;

/// <summary>脱敏规则（设计文档 8.3：规则记录版本，导出预览可核查）。</summary>
public sealed record RedactionOptions
{
    public const string RuleVersion = "redaction/2026-09-23-v1.0";

    public bool Enabled { get; init; } = true;

    /// <summary>脱敏 Authorization/Cookie/令牌/密码等键值对。</summary>
    public bool MaskCredentialHeaders { get; init; } = true;

    /// <summary>脱敏内网 IP（默认 RFC1918 全部；可缩小范围）。</summary>
    public bool MaskPrivateIpRanges { get; init; }
}

/// <summary>报告脱敏服务。文本型内容统一经过此层；原始字节（PCAPNG）不承诺脱敏。</summary>
public static partial class RedactionService
{
    [GeneratedRegex(
        @"(?i)^\s*(authorization|cookie|set-cookie|proxy-authorization|password|passwd|secret|token|api[-_]?key)\s*[:=]\s*(.+)$",
        RegexOptions.Multiline)]
    private static partial Regex CredentialLine();

    public static string Apply(string text, RedactionOptions? options = null)
    {
        var opt = options ?? new RedactionOptions();
        if (!opt.Enabled || string.IsNullOrEmpty(text)) return text;

        var result = text;
        if (opt.MaskCredentialHeaders)
        {
            result = CredentialLine().Replace(result, m =>
                $"{m.Groups[1].Value}: ********（已脱敏）");
        }
        return result;
    }

    /// <summary>对字符串做 SHA-256（证据内容哈希）。</summary>
    public static string Sha256(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data));

    public static string Sha256(string text) =>
        Sha256(Encoding.UTF8.GetBytes(text));
}
