# VPS Guard

面向个人 VPS 的分阶段加固工具包，通过 Netcatty 快捷片段调用。执行端使用 Python 3.10+ 标准库，提供 Bash 安装入口，无需 Ansible、Skill 或大模型运行时。

当前版本：0.1.0，待首台 Linux 测试 VPS 验证。真实 SSH、防火墙、内核队列、发行版差异尚未完成端到端实测，先用于可救援的测试机。测试记录见 [docs/TESTING.md](docs/TESTING.md)。

## 已确定的默认策略

- 保留当前公网 SSH 端口，采用运维账号和密钥，关闭 SSH 密码及 root 登录。
- SSH／防火墙／网络队列变更独立执行，等待新连接确认，超时尝试自动恢复。
- BBR＋fq 和 TCP 基线属于固定网络阶段；缓冲区依据输入适配。
- Swap 按需；未配置大小时保留现状，已有 Swap 默认保留。
- Tailscale 不在固定流程内，本版不提供安装动作。
- 自动安全更新、日志容量、健康检查、restic 异地备份分别执行。
- Docker／复杂防火墙／复杂队列等场景先审计，自动应用遇到冲突会停止。
- 不删除未知用户、公钥、服务或已有防火墙放行规则。

## 第一次使用

选择一台服务商控制台已验证可用的 Debian／Ubuntu、systemd 测试机，先保留原 SSH 会话。

1. 下载经过核对的版本 ZIP，或检出明确的 Git 提交；私有仓库可在自己的浏览器下载，再通过 Netcatty SFTP 上传。
2. 检查发布包的外部 SHA-256；包内 SHA256SUMS.txt 用于检查完整性。校验值也来自同一不可信来源时，不能证明来源身份。
3. 解压到独立目录；通过 sudo 安装。安装仅复制工具和示例，不应用加固。

```bash
python3 -m zipfile -e vps-guard-0.1.0.zip .
cd vps-guard-0.1.0
sudo bash install.sh
sudo vps-guard setup
sudo vps-guard audit
sudo vps-guard plan
```

如果系统没有 Python，先按发行版正常方式安装 python3。需要 Python 3.10+；不为运行本工具替换系统 Python。

导入 [netcatty/snippets.json](netcatty/snippets.json)，用法见 [netcatty/README.md](netcatty/README.md)。所有片段均为手动入口，默认先填入命令再由你检查并按回车；不要设置成连接后自动运行。

## 固定执行顺序

| 步骤 | 操作 |
| --- | --- |
| 1 | audit、plan，确认服务商救援与业务端口 |
| 2 | apply baseline：系统依赖、按配置更新、时间同步 |
| 3 | apply swap：按需单独配置；未指定大小就保留现状 |
| 4 | apply access：运维账号、公钥及 sudo 密码 |
| 5 | 新建运维账号密钥连接，执行 confirm-login |
| 6 | 原会话 apply ssh，新连接 confirm 变更编号 |
| 7 | apply firewall，新连接 confirm 变更编号 |
| 8 | 审阅应用权限、容器端口和必要的进程限制 |
| 9 | apply network，新连接 confirm 变更编号 |
| 10 | apply maintenance；配置通知与外部离线监控 |
| 11 | 配置 backup，执行备份与恢复测试 |
| 12 | verify；无待确认变更时在维护窗口重启，再次 verify |

可运行 `sudo vps-guard` 打开菜单。也可以逐条调用，例如：

```bash
sudo vps-guard apply access
sudo vps-guard apply network
sudo vps-guard pending
sudo vps-guard verify
```

没有“一键全部加固”：跨越登录认证、网络入口和恢复验证的操作，按以上阶段完成。

## 配置与凭据

- 主机配置：/etc/vps-guard/config.json，root 所有、权限 600。
- 配置示例：[config.example.json](config.example.json)。实际配置不进入 GitHub。
- 运维公钥留在配置中；私钥保留在客户端，不复制到 VPS。
- 运维账号使用本地 sudo 密码；access 阶段会按需提示设置，不永久配置无限制免密 sudo。
- 备份与通知引用本机 root 专用 env 文件，示例包含占位值。
- env 文件只按 KEY=value 读取，不执行 Shell 展开。

## 边界和恢复

自动恢复依赖 systemd、机器在线以及可恢复的配置；不能替代独立救援入口。等待确认期间不要重启或同时修改相同设置。配置被后续操作改动时，工具停止陈旧恢复，避免覆盖新改动。

不自动回退软件升级、密码、组成员及创建账号；不删除账号数据，不自动卸载已加载内核模块。恢复是针对本次管理的配置，不是整机快照。

本机检查不能证明公网端口安全、通知已经送达、数据库恢复一致或网络已经提速。verify 会明确输出 failed、pending_manual、not_tested；人工验收可通过 attest 记录结果。

详细步骤与恢复方法见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。

## 开发检查与打包

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_release.py
```

输出 ZIP 与 SHA-256 文件位于 dist/。打包采用明确文件清单，排除主机配置、凭据及报告。修改源码后需重新生成并提交 SHA256SUMS.txt，CI 会核对。
