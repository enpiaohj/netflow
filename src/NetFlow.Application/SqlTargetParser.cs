using System.Text.RegularExpressions;

namespace NetFlow.Application;

/// <summary>
/// 解析“SQL 实例/端口”输入：数字 = 固定端口（如 1433）；名称 = 命名实例（走 Browser 1434 发现）；
/// 空或默认实例名（MSSQLSERVER）= 默认实例，直接测 TCP 1433。
/// </summary>
public static partial class SqlTargetParser
{
    public sealed record Result(int? Port, string? InstanceName, string? Error);

    [GeneratedRegex(@"^\s*(\d{1,5})(?:\s|$)")]
    private static partial Regex PortText();

    [GeneratedRegex(@"^[A-Za-z0-9_$#@.\-]{1,128}$")]
    private static partial Regex InstanceName();

    public static Result Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return new Result(null, null, null);

        var m = PortText().Match(text);
        if (m.Success)
        {
            return int.TryParse(m.Groups[1].Value, out var port) && port is >= 1 and <= 65535
                ? new Result(port, null, null)
                : new Result(null, null, "SQL 端口需为 1–65535");
        }

        // 只取第一个词（下拉预置带中文说明）；允许“服务器\实例”写法，只取实例部分
        var name = text.Trim().Split(' ', '\t', '（', '(')[0];
        var slash = name.LastIndexOf('\\');
        if (slash >= 0) name = name[(slash + 1)..];

        if (name.Equals("MSSQLSERVER", StringComparison.OrdinalIgnoreCase))
            return new Result(null, null, null);

        return InstanceName().IsMatch(name)
            ? new Result(null, name, null)
            : new Result(null, null, "实例名只能包含字母、数字及 _ $ # @ . -");
    }
}
