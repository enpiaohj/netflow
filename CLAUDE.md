# NetFlow 项目规则（项目级，优先于用户级全局规则）

## 产品标识

- 产品名：NetFlow（正式发布产物名）
- 仓库名：netflow（GitHub，Private，建立远端前需用户确认）
- 本地仓库根：`D:\AIProjects\NetFlow`

## 版本与发布

- 起始版本 v0.1.0；M1 诊断闭环完成时 v1.0.0。
- 发布产物命名：`NetFlow-v<MAJOR.MINOR.PATCH>-win-x64.<ext>`（如 `NetFlow-v0.1.0-win-x64.exe`）。
- 安装包形态：自包含单文件 exe + 便携 ZIP 为默认交付；MSIX 待代码签名证书就绪后评估。
- 发布流程遵循全局 `rules/release.md`；`releases/vX.Y.Z/` 中 `source/` 与 `CHANGELOG.md` 入库，二进制不入库。

## 构建命令（来自项目本身）

```
dotnet build NetFlow.sln -c Debug
dotnet test NetFlow.sln --filter FullyQualifiedName!~Integration
dotnet test tests/NetFlow.IntegrationTests   # 需真实环境 + testsettings.local.json
dotnet publish src/NetFlow.Desktop -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true
```

- 目标框架：类库 `net10.0`；Desktop / Windows / CaptureHost 用 `net10.0-windows`。
- 提交前最低验证：`dotnet build` + 领域/探针单元测试。

## 安全红线

- **任何真实凭据不得入库**：集成测试凭据只放 `tests/NetFlow.IntegrationTests/testsettings.local.json`（已 gitignore）。
- 测试环境主机名 / IP 可以写入仓库（企业内网测试环境约定）；密码、账号一律掩码。
- 诊断功能默认只读；不得在诊断流程中修改用户系统配置。
- 凭据在内存中使用 DPAPI CurrentUser 保护存储；不写日志、不写报告、不写 JSON/HTML。

## 测试环境约定（内网测试域 corp.example.com）

| 角色 | 主机 | 用途 |
|---|---|---|
| 域控 | dc（192.168.10.11，dc01） | AD/DNS/Kerberos/LDAP/SMB/NTP 场景 |
| 成员服务器 | fs（192.168.10.15，fs01） | 文件共享 / SQL Server / IIS(HTTP) / RDP / WinRM |
| ESXi | 192.168.10.200 | TLS 证书名称不匹配用例 |
| 开发机 | 192.168.10.100，工作组机器，多网卡（3 虚拟网卡） | 源地址选择 / 抓包提权测试 |

- 本机未加域：Kerberos SSO 用例按「显式凭据」级别验证，UI 需如实标注视角限制。
- 集成测试账号：域管理员级（testadmin）与普通域用户（testuser01）双身份，验证有权/无权路径。

## 架构约束（源自设计文档 v1.0）

- 状态判定必须走 `NetFlow.Domain` 的类型化结果与状态矩阵，UI 文本不得作为事实源。
- UDP 无响应 = 未确认；DNS NXDOMAIN = 服务有响应 + 查询业务失败；TCP 连接成功 = 仅传输层成功。
- 外部命令（Pktmon/TShark/PowerShell）必须 `ArgumentList` 传参、固定路径、限时、记录退出码与版本。
- 抓包宿主为一次性提权子进程，只接受参数文件校验后的采集参数，按 runId 写限定目录。
- 每个探针的「未实现阶段」必须输出「未支持/未检查」，不得用 TCP 结果冒充协议验证。

## 文档

- 项目文档放 `docs/`，命名 `YYYY-MM-DD-内容-v<版本>.md`。
- UI 概念图不入库，路径见 README。
