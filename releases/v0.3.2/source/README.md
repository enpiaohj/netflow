# NetFlow —— Windows 网络与服务诊断工作台

面向企业 IT 工程师的网络与服务诊断桌面应用。从一个客户端或服务器出发，选择目标与业务场景，依次执行本机环境检查、DNS、路径、TCP/UDP 端口、应用协议检查、抓包、服务与事件日志检查，最终输出附有证据、结论等级、限制和下一步建议的诊断报告。

当前版本：**v0.3.2**（详见 [CHANGELOG.md](CHANGELOG.md)）。许可证：[GPL-3.0](LICENSE)。

> 本产品名称“NetFlow”与 Cisco 的 NetFlow 流量导出协议无关：NetFlow 是面向 Windows 的网络与服务连通性诊断工具，不采集或分析 NetFlow / IPFIX 流量记录。

## 产品验收核心

- 从填写目标到导出报告构成完整闭环。
- 每个结果必须标注：测试视角、观察事实、结论等级、证据来源、限制和下一步。
- 严禁三类误判：
  - 发送成功 ≠ UDP 端口开放（无应答 = 未确认）；
  - 本机无应答 ≠ 防火墙丢包；
  - 端口可连接 ≠ 服务可用。
- 测试必须明确源网络：所有检查从用户选定的源网卡发出，证据中记录实际使用的源地址；无法指定源地址的检查会在结果中注明。

## 功能概览

| 页面 | 主要功能 |
|---|---|
| 总览 | 本机网络状态、快速入口、最近诊断 |
| 快速测试 | TCP 端口、UDP 端口（原始 UDP / NTP 协议）、DNS 解析、HTTP/TLS、Ping/路径、NTP；测试完成后默认显示摘要 |
| 场景诊断 | 9 个内置场景模板（AD、DC 间、Exchange、SQL Server、Web/API、SMB、远程管理、NTP 等），支持自定义模板；可同时抓包；导出 HTML/JSON/CSV 报告 |
| 抓包分析 | 基于 Pktmon：记录后分析（生成 PCAPNG 并自动分析异常）或实时显示；导入 PCAPNG；可选 TShark 深入解析 |
| 服务与日志 | 服务状态、事件日志（按日志、级别、时间范围、事件 ID 筛选）、监听端口；远程查询前可检测所需端口 |
| 本机网络 | 网络适配器、路由查询、监听端口、防火墙规则 |
| 批量任务 | 主机 × 端口包批量检测（12 个内置端口包，可保存自定义端口包）；持续监测 |
| 历史报告 | 搜索、打开报告、重新运行、打开证据文件夹 |
| 设置 | 常规、抓包与分析、数据与隐私、AI 分析、关于与环境 |

窗口顶部为全局“源网卡”选择，默认使用带默认网关的以太网卡。

### AI 分析

在“快速测试”“场景诊断”“抓包分析”页面可将结果（先脱敏）发送给 AI 模型，获取原因分析与排查建议。当前支持 DeepSeek，需在“设置 → AI 分析”中配置 API Key。发送前可预览全部内容；密码、令牌等敏感字段始终被屏蔽。详见 [用户手册](docs/2026-09-24-NetFlow用户手册-v1.2.md#8-ai-分析)。

## 技术栈

| 层 | 选型 |
|---|---|
| UI | .NET 10 LTS + WPF（CommunityToolkit.Mvvm） |
| 检查核心 | C# 类库，async/await、CancellationToken、Socket/HttpClient/SslStream；ICMP 使用 iphlpapi `IcmpSendEcho2Ex` 以支持指定源地址 |
| LDAP | System.DirectoryServices.Protocols |
| SQL 认证测试 | Microsoft.Data.SqlClient |
| 抓包 | Pktmon；主程序以管理员身份重新启动自身（`--capture-host`）作为一次性抓包进程 |
| 本地数据 | SQLite（Microsoft.Data.Sqlite）：诊断记录、设置、端口包、输入历史；迁移 + 单连接写锁 |
| 密钥保护 | Windows DPAPI（当前用户） |
| 报告 | 离线 HTML / JSON / CSV / 证据 ZIP |

## 仓库结构

```
src/
  NetFlow.Domain/          结果、证据、状态判定矩阵、接口（纯领域模型）
  NetFlow.Probes/          DNS/TCP/UDP/ICMP/HTTP·TLS/SMTP/LDAP/SQL/SMB/RDP·WinRM·SSH/NTP 检查
  NetFlow.Windows/         网卡、路由、防火墙、服务、事件日志（含筛选构造）、外部命令
  NetFlow.Capture/         Pktmon 控制、抓包进程逻辑、实时输出解析、PCAPNG 解析与会话分析
  NetFlow.CaptureHost/     独立抓包程序（兼容保留；主程序已可自行承担抓包进程）
  NetFlow.Persistence/     SQLite、迁移、留存
  NetFlow.Reporting/       HTML/JSON/CSV/证据 ZIP、脱敏
  NetFlow.Application/     任务编排、场景模板、端口包、设置、AI 分析、源网卡目录
  NetFlow.Desktop/         WPF 页面与控件
  NetFlow.Cli/             命令行接口
tests/
  NetFlow.Domain.Tests/         领域模型、状态矩阵、端口包、事件筛选、持久化、AI、实时解析
  NetFlow.Probes.Tests/         协议解析、状态判定、源地址如实性（离线）
  NetFlow.IntegrationTests/     真实环境集成测试（凭据走本地未跟踪配置）
docs/                           设计文档、变更说明、用户手册
scripts/                        辅助脚本（应用图标生成）
releases/                       正式版本快照（source 与 CHANGELOG 入库，二进制不入库）
```

## 构建与测试

```
dotnet build NetFlow.slnx -c Debug
dotnet test NetFlow.slnx --filter "FullyQualifiedName!~Integration"
dotnet test tests/NetFlow.IntegrationTests        # 需要真实环境与 testsettings.local.json
dotnet run --project src/NetFlow.Cli
dotnet publish src/NetFlow.Desktop -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

发布产物为单个 `NetFlow.exe`（自包含，无需安装 .NET）。抓包不再依赖同目录的 `NetFlow.CaptureHost.exe`。

## 运行环境与数据位置

- Windows 11 x64（Windows Server 2022/2025 按能力适配）。
- 抓包需要管理员权限；开始抓包时会提示用户账户控制（UAC）。
- 数据保存在 `%LOCALAPPDATA%\NetFlow\`：

| 位置 | 内容 |
|---|---|
| `netflow.db` | SQLite：诊断记录、设置、端口包、输入历史 |
| `evidence\<任务 ID>\` | 报告（HTML/JSON/CSV）、抓包文件 |
| `user-templates.json` | 自定义场景模板 |

## 集成测试环境配置

集成测试需要真实环境。复制 `tests/NetFlow.IntegrationTests/testsettings.example.json` 为 `testsettings.local.json` 并填入实际凭据。`testsettings.local.json` 已被 `.gitignore` 排除，**严禁提交任何真实凭据**（包括 AI 服务的 API Key）。

UI 概念设计图不随仓库分发。

## 隐私与数据

- 不收集遥测、崩溃报告或使用统计，不向开发者或第三方发送使用数据。
- 诊断请求仅发往用户指定的目标；诊断功能默认只读。
- 唯一可能的对外请求来自“AI 分析”：仅在用户启用并确认后，将脱敏后的摘要发送至所配置的 API 地址（默认 DeepSeek，须为 https）。API Key 由用户自行提供，以 DPAPI（当前用户）加密存入本地数据库。
- 设置、端口包、输入历史与诊断记录均保存在本机 SQLite 数据库中。

## 许可证

按 GNU General Public License v3.0 发布，全文见 [LICENSE](LICENSE)。随发布产物分发的第三方组件及其许可证见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。安全问题请按 [SECURITY.md](SECURITY.md) 报告。

## 相关文档

- [用户手册 v1.2](docs/2026-09-24-NetFlow用户手册-v1.2.md)：各页面操作、端口包、事件日志筛选、抓包方式、AI 分析、数据与隐私。
- [设计变更说明 v1.3](docs/2026-09-24-NetFlow设计变更说明-v1.3.md)：相对设计方案 v1.0 的架构与数据模型变更及决策依据。
- [完整产品设计与技术实施方案 v1.0](docs/2026-09-23-NetFlow完整产品设计与技术实施方案-v1.0.md)
- [CHANGELOG.md](CHANGELOG.md)：版本变更记录。
