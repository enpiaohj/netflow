using System.Security.Cryptography;

namespace NetFlow.Windows;

/// <summary>
/// 凭据保护（设计文档 8.4）：Windows DPAPI CurrentUser 范围。
/// 秘密不写日志、不写明文配置；内存中仅短暂解出。
/// </summary>
public sealed class DpapiCredentialProtector
{
    public string Protect(string plaintext)
    {
        if (OperatingSystem.IsWindows())
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(plaintext);
            var encrypted = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(encrypted);
        }
        throw new PlatformNotSupportedException("DPAPI 仅在 Windows 可用");
    }

    public string Unprotect(string ciphertext)
    {
        if (OperatingSystem.IsWindows())
        {
            var bytes = Convert.FromBase64String(ciphertext);
            var decrypted = ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser);
            return System.Text.Encoding.UTF8.GetString(decrypted);
        }
        throw new PlatformNotSupportedException("DPAPI 仅在 Windows 可用");
    }
}
