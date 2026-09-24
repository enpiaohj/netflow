# 第三方组件声明

NetFlow 按 GNU GPL-3.0 发布（见 [LICENSE](LICENSE)）。发布产物（自包含单文件 `NetFlow.exe`）包含下列第三方组件，其许可证均与 GPL-3.0 兼容。各组件的版权与许可证文本以其官方发布为准。

## 随发布产物分发的组件

| 组件 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| .NET 运行时与基础类库（Microsoft） | 10.0 | MIT | 自包含运行时 |
| Windows Presentation Foundation（Microsoft） | 10.0 | MIT | 桌面界面 |
| CommunityToolkit.Mvvm | 8.4.2 | MIT | 界面数据绑定辅助 |
| Microsoft.Data.SqlClient | 7.1.0 | MIT | SQL Server 登录阶段检查 |
| Microsoft.Data.Sqlite | 10.0.12 | MIT | 本地 SQLite 数据存取 |
| SQLitePCLRaw（bundle_e_sqlite3 / core） | 2.1.x | Apache-2.0 | SQLite 原生库绑定 |
| SQLite | — | 公有领域 | 嵌入式数据库引擎 |
| System.DirectoryServices.Protocols | 10.0.12 | MIT | LDAP 检查 |
| System.Security.Cryptography.ProtectedData | 10.0.12 | MIT | DPAPI 保护 API Key |
| System.ServiceProcess.ServiceController | 10.0.12 | MIT | 服务状态检查 |

以上列表按 `*.csproj` 中的直接引用及其传递依赖整理；升级依赖时应同步更新本文件。

## 仅用于开发与测试（不随发布产物分发）

| 组件 | 许可证 |
|---|---|
| xunit、xunit.runner.visualstudio | Apache-2.0 |
| Microsoft.NET.Test.Sdk | MIT |
| coverlet.collector | MIT |

## 运行时调用的外部工具（不随产品分发）

| 工具 | 说明 |
|---|---|
| Pktmon | Windows 内置的抓包工具，由系统提供。 |
| TShark（Wireshark） | 可选。仅当用户自行安装后，用于深入解析 PCAPNG；本产品不包含、不分发。 |

## 其他

- 应用图标由本项目自制，随 GPL-3.0 发布。
- “NetFlow”为本产品名称，与 Cisco 的 NetFlow 流量导出协议无关。
