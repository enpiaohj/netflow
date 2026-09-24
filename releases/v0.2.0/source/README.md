# NetFlow —— Windows 网络与服务诊断工作台

面向企业 IT 工程师的网络与服务诊断桌面应用：从一个客户端或服务器出发，选择目标与业务场景，执行本机环境检查、DNS、路径、TCP/UDP、应用协议探针、抓包、服务及事件检查，最终输出附有证据、结论等级、限制和下一步建议的诊断报告。

## 产品验收核心

- 从填写目标到导出报告构成完整闭环。
- 每个结果必须标注：测试视角、观察事实、结论等级、证据来源、限制和下一步。
- 严禁三类误判：
  - 发送成功 ≠ UDP 端口开放（无响应 = 未确认）；
  - 本机无响应 ≠ 防火墙丢包；
  - 端口可连接 ≠ 服务可用。

## 技术栈

| 层 | 选型 |
|---|---|
| UI | .NET 10 LTS + WPF + MVVM（CommunityToolkit.Mvvm） |
| 探针核心 | C# 类库，async/await、CancellationToken、Socket/HttpClient/SslStream |
| LDAP | System.DirectoryServices.Protocols |
| SQL 认证测试 | Microsoft.Data.SqlClient |
| 抓包 | Pktmon + 独立提权采集宿主（一次性提权子进程方案） |
| 本地数据 | Microsoft.Data.Sqlite（迁移 + 单写队列） |
| 报告 | 离线 HTML / JSON / CSV / 证据 ZIP |

## 仓库结构

```
src/
  NetFlow.Domain/          结果、证据、规则、接口（纯领域模型）
  NetFlow.Probes/          DNS/TCP/UDP/ICMP/HTTP·TLS/SMTP/LDAP/SQL/SMB/RDP·WinRM·SSH 探针
  NetFlow.Windows/         网卡、路由、防火墙、服务、事件适配
  NetFlow.Capture/         Pktmon 协调、PCAPNG、会话分析
  NetFlow.CaptureHost/     按需提权本机抓包宿主
  NetFlow.Persistence/     SQLite、迁移、留存
  NetFlow.Reporting/       HTML/JSON/CSV/证据 ZIP
  NetFlow.Application/     任务编排、状态机、模板、报告用例
  NetFlow.Desktop/         WPF 页面、控件、MVVM
  NetFlow.Cli/             命令行接口
tests/
  NetFlow.Domain.Tests/         领域模型与状态矩阵
  NetFlow.Probes.Tests/         协议解析与状态判定（离线夹具）
  NetFlow.IntegrationTests/     真实环境集成测试（凭据走本地未跟踪配置）
docs/                           设计文档
```

## 构建与测试

```
dotnet build NetFlow.sln -c Debug
dotnet test NetFlow.sln -c Debug
dotnet run --project src/NetFlow.Cli
dotnet publish src/NetFlow.Desktop -c Release -r win-x64 --self-contained true
```

## 集成测试环境配置

集成测试需要真实环境。复制 `tests/NetFlow.IntegrationTests/testsettings.example.json` 为 `testsettings.local.json` 并填入实际凭据。`testsettings.local.json` 已被 `.gitignore` 排除，**严禁提交任何真实凭据**。

UI 概念设计图（13 页）位于产品设计工作区，不入 Git 历史：
`（产品设计工作区）`

## 相关文档

- [2026-09-23-NetFlow完整产品设计与技术实施方案-v1.0.md](docs/2026-09-23-NetFlow完整产品设计与技术实施方案-v1.0.md)
