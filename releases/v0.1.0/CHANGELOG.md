# NetFlow v0.1.0

发布日期：2026-09-24

Windows 桌面端「网络与服务诊断工作台」首个可用版本：从填写目标到导出报告的诊断闭环已打通，包含 11 类协议探针、场景模板、Pktmon 提权抓包、持续监测与离线报告。

## Added

- 领域模型与统一状态判定矩阵：类型化结果/证据/发现，UDP 无响应=未确认、拒绝≠丢包归因等红线内建于规则（规则版本 `rules/2026-09-23-v1.0`）
- 11 类协议探针：DNS（RFC1035 线缆协议，含压缩指针/TCP 重试）、TCP、UDP、NTP、ICMP/路径、HTTP（分阶段计时+重定向链）、TLS（证书链完整检查）、SMTP、LDAP、SQL Server（SSRP 实例发现+登录）、SMB2 协商、RDP/WinRM/SSH
- 诊断编排：任务状态机（崩溃/取消保留部分结果）、9 个内置场景模板（AD 客户端→DC、DC 间、Exchange、SQL、Web、SMB、远程管理、NTP）、发现与下一步建议生成
- 抓包：Pktmon 一次性提权采集宿主 + 「命名事件/停止文件」双通道停止 + 语法自适应（新版 capture / 旧版 etw，实机验证）、PCAPNG 流式解析与会话分析（SYN 无应答/重传候选/UDP 未确认）、TShark 可选深度解析（不捆绑）
- 持续监测：低频定时探针（最小 30 秒），休眠/断网记录采样缺口而非目标故障
- 持久层：SQLite 单写队列 + 留存清理；数据库不可用时诊断功能降级运行
- 报告：完全离线 HTML / JSON / CSV，脱敏服务（凭据键值抑制）
- 桌面 UI（WPF，9 页）：总览/快速测试/场景诊断/抓包分析/服务与日志/本机网络/批量任务/历史报告/设置；页面实例缓存（切换不丢任务）、顶栏运行中指示、KPI 统计卡、事件时间线、彩色结论徽章
- CLI：单探针命令与场景诊断（报告输出到 `%LOCALAPPDATA%\NetFlow\evidence\<runId>\`）
- 可观测性：AppLog 滚动文件日志（14 天保留）+ 三层全局异常兜底
- 用户模板：内置模板只读，副本编辑递增 MINOR 版本，执行固化快照

## Fixed / Improved

- 抓包停止通道：控制器预创建命名事件并保持句柄存活，停止文件兜底（修复事件从未创建/句柄即释放两处缺陷）
- pktmon 语法自适应：实机验证新版语法（`start --capture --pkt-size --file-name`、`filter add <name>`、`etl2pcap --drop-only`），候选依次尝试并逐项记录退出码
- 宿主存活探测：启动后 5 秒内未写出状态文件且已退出 → 立即报部署/策略问题，不再假装抓包中
- 停止等待改真异步（原 Thread.Sleep 会冻结 UI 最长 60 秒）；停止超时保留重试入口
- SQLite 读写全部串行化（修复并发访问冲突）；PCAPNG 流式解析（内存与文件大小无关，限 20 万包）
- HTTP 探针默认直连（内网诊断），按底层套接字错误细分传输分类；SMTP EHLO 非 250 如实判服务层错误
- DNS 线缆解析拒绝向前压缩指针（恶意报文防护）
- UI 交互：运行中可取消、Enter 触发、内联校验提示、结果行与证据联动、历史搜索过滤与重跑

## Known Issues

- 抓包需要 UAC 提权（一次性子进程）；拒绝后仅执行普通探针，界面如实标注
- 本开发机未加域：Kerberos SSO/机器账户路径仅验证到「显式凭据」级别
- TShark 为用户自装可选组件，未安装时深度解析不可用（内置分析不受影响）
- CLI 为基础版（单探针 + 场景诊断），批量/监测尚未接入
- 模板编辑为文件级（user-templates.json），无可视化编辑器
- 抓包加密负载不解密；Pktmon 多组件观察需按采集层次去重（界面已提示）

## Verification

- Build：Release 全解决方案构建 0 警告 0 错误（.NET 10.0.401，win-x64 自包含）
- Tests：52/52 通过（领域 20 + 探针 17 + 真实环境集成 15，Release 配置）
- 实机集成：corp.example.com 测试域——DC 七端口+NTP、文件服务器 SMB/SQL/RDP/WinRM、ESXi TLS 证书不匹配用例、UIA 真实抓包 96 个 ICMP 包端到端验证
- Platform：Windows 11 x64（Windows Server 2022/2025 按能力矩阵适配）
- Architecture：x64 自包含单文件（NetFlow.exe + NetFlow.CaptureHost.exe）

## Git

- Tag：`v0.1.0`
- 发布提交：（见下方 tag 指向）
- 代码基线：`fdb3bcc`（发布提交仅新增本快照与 CHANGELOG，代码与基线完全一致）
