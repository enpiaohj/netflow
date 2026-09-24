# NetFlow 项目规则（项目级，优先于用户级全局规则）

## 产品标识

- 产品名：NetFlow（正式发布产物名）
- 仓库名：netflow（GitHub，Private，建立远端前需用户确认）
- 本地仓库根：`D:\AIProjects\NetFlow`

## 版本与发布

- 起始版本 v0.1.0；当前 v0.3.0；M1 诊断闭环完成时 v1.0.0。
- 发布产物命名：`NetFlow-v<MAJOR.MINOR.PATCH>-win-x64.<ext>`（如 `NetFlow-v0.3.0-win-x64.exe`）。
- 版本号位置（发布时同步更新）：`Directory.Build.props`、`NetFlow.Domain/NetFlowInfo.cs`（Version、UserAgent）、`NetFlow.Cli/Program.cs` 帮助文本、`MainWindow.xaml` 版本占位。
- 安装包形态：自包含单文件 exe（单个 exe 即可抓包，无需同目录宿主）+ 便携 ZIP 为默认交付；MSIX 待代码签名证书就绪后评估。
- 发布流程遵循全局 `rules/release.md`；`releases/vX.Y.Z/` 中 `source/` 与 `CHANGELOG.md` 入库，二进制不入库。

## 构建命令（来自项目本身）

```
dotnet build NetFlow.slnx -c Debug
dotnet test NetFlow.slnx --filter "FullyQualifiedName!~Integration"
dotnet test tests/NetFlow.IntegrationTests   # 需真实环境 + testsettings.local.json
dotnet publish src/NetFlow.Desktop -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

- 目标框架：类库 `net10.0`；Desktop / Windows / Capture / CaptureHost 用 `net10.0-windows`。
- 提交前最低验证：`dotnet build` + 领域/探针单元测试。

## 安全红线

- **任何真实凭据不得入库**：集成测试凭据只放 `tests/NetFlow.IntegrationTests/testsettings.local.json`（已 gitignore）。
- 测试环境主机名 / IP 可以写入仓库（企业内网测试环境约定）；密码、账号一律掩码。
- 诊断功能默认只读；不得在诊断流程中修改用户系统配置。
- 凭据在内存中使用 DPAPI CurrentUser 保护存储；不写日志、不写报告、不写 JSON/HTML。
- AI 服务 API Key 仅以 DPAPI 密文存入本地数据库；不得出现在代码、测试、文档、脚本、日志或提交中。测试用密钥只通过环境变量或应用设置页传入。
- AI 分析仅发送脱敏后的摘要文本，敏感字段屏蔽不可关闭；API 地址必须使用 https（本机回环地址除外）。

## 测试环境约定（示例域 corp.example.com；真实值见本地 testsettings.local.json）

| 角色 | 主机 | 用途 |
|---|---|---|
| 域控 | dc（192.168.10.11，示例主机名 dc01） | AD/DNS/Kerberos/LDAP/SMB/NTP 场景 |
| 成员服务器 | fs（192.168.10.15，示例主机名 fs01） | 文件共享 / SQL Server / IIS(HTTP) / RDP / WinRM |
| ESXi | 192.168.10.200 | TLS 证书名称不匹配用例 |
| 开发机 | 192.168.10.100，工作组机器，多网卡（以太网 + 3 个虚拟网卡） | 源网卡选择 / 抓包提权测试 |

- 本机未加域：Kerberos SSO 用例按「显式凭据」级别验证，UI 需如实标注视角限制。
- 集成测试账号：域管理员级（testadmin）与普通域用户（testuser01）双身份，验证有权/无权路径。

## 架构约束（源自设计文档 v1.0，变更见 v1.1 变更说明）

- 状态判定必须走 `NetFlow.Domain` 的类型化结果与状态矩阵，UI 文本不得作为事实源。
- UDP 无响应 = 未确认；DNS NXDOMAIN = 服务有响应 + 查询业务失败；TCP 连接成功 = 仅传输层成功。
- 外部命令（Pktmon/TShark/PowerShell）必须 `ArgumentList` 传参、固定路径、限时、记录退出码与版本。
- 抓包由主程序以 `--capture-host` 参数经 UAC 重新启动自身完成（一次性提权，宿主模式不创建窗口、不初始化应用服务）；只接受参数文件校验后的采集参数，按任务 ID 写限定目录；主程序保持标准权限。
- 实时抓包的 pktmon 缓冲文件必须限定在任务目录并限制大小，停止后删除。
- 测试必须有明确的源网卡（无“自动”）：探针按所选网卡绑定源地址，无法绑定的检查必须在证据中注明，不得把请求的源地址写成实际源地址。
- 应用数据（设置、端口包、输入历史）存入 SQLite（schema v2，迁移只增表）；数据库不可用时降级为仅内存，不得影响诊断功能。
- 每个探针的「未实现阶段」必须输出「未支持/未检查」，不得用 TCP 结果冒充协议验证。

## 文档

- 项目文档放 `docs/`，命名 `YYYY-MM-DD-内容-v<版本>.md`。
- 许可证 GPL-3.0；依赖变更时同步更新 `THIRD-PARTY-NOTICES.md`。仓库中不得出现真实内网域名、主机名、账号；示例值用 `corp.example.com` / `dc01` / `fs01`。
- 现有文档：设计方案 v1.0、设计变更说明 v1.1、用户手册 v1.0；根目录 `README.md`、`CHANGELOG.md` 随版本发布同步更新。
- 功能或架构变更时同步更新：README、用户手册、设计变更说明（新增变更项与缺陷修复）、CHANGELOG。
- UI 概念图不入库，路径见 README。

## 界面文案规范

所有面向用户的文字（功能名称、按钮、标签、提示、说明、状态、错误信息、通知、交互反馈）遵循以下规则，风格参考 Windows、Microsoft Office：

- **风格**：专业、规范、准确、简洁、清晰。一句话说明含义、当前状态、结果或下一步；避免口语化、娱乐化、AI 腔、开发者术语和模糊表述。
- **术语统一**：同一概念全程只用一个词，如：源网卡、端口包、检查项、传输层/协议层、证据文件夹、无应答、未确认、重新运行。不使用“宿主”“提权”“打码”“重跑”“探针”（面向用户处）等内部或口语用语。
- **错误信息**：先说明发生了什么（“无法……”），再给出可执行的下一步；不显示异常类型名、内部标识（如 runId）或代码术语。
- **句式**：按钮和菜单用动词短语（“开始检测”“另存为”）；标签用名词；说明与状态文字为完整句并以句号结束，长度不超过两行；占位提示和工具提示不加句号；数值范围写作“应为 1–65535”。
- **图标**：使用 Segoe MDL2 Assets / Segoe Fluent Icons 字体图标，不使用表情符号。
- **可访问性**：图标 + 文字组合的控件必须设置 `AutomationProperties.Name`；列表项类型需重写 `ToString()` 返回显示名称。
