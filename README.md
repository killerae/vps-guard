# VPS Guard — 个人默认方案

当前版本：0.3.1。面向单台 Debian／Ubuntu＋systemd VPS，Python 3.10+。在线入口先询问一次是否确认开始；确认后不再询问公钥、账号、业务端口、带宽、RTT、Swap 或备份选择，自动执行固定方案，结束后输出实际操作报告。

**这是 killerae 的个人专用预设。** 默认账号 ops，内置 lu-admin 公钥，并启用免密 sudo。只有持有对应私钥的人应在自己的 VPS 使用此预设；其他人复用前必须更换 `vps_auto.py` 中的 PUBLIC_KEY。密钥登录后拥有完整管理员权限，私钥必须由你妥善保管，不能上传服务器或 GitHub。

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID5kxFrMhEWqeZxm5P4cr09PKUMUZRVDSRvzZ4cwEVAE lu-admin
```

## 一键开始

保留原 SSH 窗口，在 VPS 终端执行：

```bash
bash -c 'u=https://raw.githubusercontent.com/killerae/vps-guard/main/bootstrap.sh; f=$(mktemp) && (curl -fsSL "$u" -o "$f" || wget -qO "$f" "$u") && bash "$f"; r=$?; rm -f -- "$f"; exit "$r"'
```

入口完整下载后先显示默认方案和「是否确认开始安装／加固？[y/N]」。只有明确输入 y／yes 才继续下载、校验和安装固定版本，并执行默认方案；回车、n／no 或输入结束都会取消，本次不安装或应用加固。即使已安装同版本，进入快速续跑前也会先确认。仅下载校验的 --download-only 模式不会运行加固，也不会询问此确认。需要 curl 或 wget 至少一个可用；不会要求 GitHub Token 或私钥。入口来自 main，使用者须信任仓库维护者和 HTTPS；固定入口时可把 main 换成自己审阅过的 bootstrap 提交 SHA。

**从旧版升级：先 Ctrl+C 退出当前旧向导，再执行上述命令。** 安装器会拒绝覆盖运行中的向导，以及待确认、未完成或恢复失败的事务。先用旧工具确认／恢复这些变更，随后再升级。旧配置和旧代码在 VPS 本地保留备份，不上传 GitHub。

以后输入 `sudo vps-guard` 打开菜单，直接回车或选 1 执行／续跑。也可以直接执行 `sudo vps-guard auto`。同版本已完成时只重新验收并展示报告，不重复升级；要明确开始新一轮，使用 `sudo vps-guard auto --restart`。

## 固定默认方案

| 项目 | 默认行为 |
| --- | --- |
| 系统 | 刷新软件源、升级可升级软件、安装依赖，保留已有软件配置；UTC 和时间同步 |
| 账号 | ops＋上面的指定公钥；免密 sudo，经 visudo 及实际免密权限检查 |
| SSH | 保留当前实际端口；新账号验证后关闭 root／密码 SSH；保留 SFTP、TCP 转发 |
| 防火墙 | 默认业务端口固定为 443/TCP＋443/UDP，即使服务尚未监听也预先放行；SSH 实际管理端口单独保留；不默认放行 80 或沿用旧配置中的其他业务端口 |
| 现有业务 | 未确认的公网监听、Docker、其他防火墙／自定义规则存在时，保留原防火墙并在报告说明，不猜测或扩大开放 |
| 防爆破 | 防火墙阶段兼容时配置实际 SSH 端口对应的 Fail2ban；冲突场景不冒充已完成 |
| 网络 | 启用当前内核 BBR＋实际出口 fq；基础 TCP 调整，保留缓冲区上限；复杂队列或内核不支持时保留现状并报告 |
| Swap | 不新建，不关闭已有 Swap |
| 更新与日志 | 每日安全更新、禁止自动整机重启；持久日志上限 200 MiB、运行日志 50 MiB；每小时健康检查 |
| Tailscale | 不安装 |
| 备份与通知 | 本地保存本次配置恢复快照；没有外部目的地／凭据时不虚构异地备份和告警接入；已配置的可用备份可沿用 |

软件通过当前系统配置的 APT 源在线安装候选版本，并非封装软件二进制或无条件追上游最新版。工具逻辑固定版本。不自动更换第三方内核，不自动测速消耗流量，不初始化未知备份仓库，不删除未知账号、公钥、服务或现有 UFW 放行规则。

## 唯一需要配合的地方：SSH 新连接验证

脚本不会替你证明本机私钥能登录。保留原窗口：

1. 准备 ops 和公钥后，在 Netcatty **新建 ops 的独立密钥连接**，执行 `sudo vps-guard continue`。
2. 原窗口自动部署所选网络、防火墙和 SSH，SSH 最后修改。
3. 提示部署完成后，**再新建一条管理连接**，执行同一句 `sudo vps-guard continue`。
4. 验证通过，取消 10 分钟定时恢复，自动继续维护和报告。

不再有配置选择题；日志不足时，认证验证仍可能要求 KEY／NEW 的人工确认。Netcatty 只新开终端标签但复用旧 SSH 传输不算新连接。原窗口退出时，continue 会在当前连接续跑。

控制台验证不再作为问答，也不会自动伪造“已验证”。未记录验证时报告会注明。**待确认期间不要重启、覆盖工具代码或同时修改相同配置。** 超时恢复依赖 systemd、机器在线及旧配置可恢复，不能代替服务商救援。

## 操作报告

终端最后列出：已完成／已符合、未执行／保留现状、执行失败／暂停、待验证事项。失败也会保存部分进度和恢复结果。

```bash
sudo vps-guard report
sudo cat /var/lib/vps-guard/last-report.json
```

文字报告：`/var/lib/vps-guard/last-report.txt`。JSON 还记录本轮事务、执行命令结果、回滚状态、公钥指纹及业务端口，适合交给 AI 后续调整。实际配置在 `/etc/vps-guard/config.json`，状态目录仅 root 可访问，不会上传 GitHub。

软件升级、账号与组成员操作不提供自动逆转；文件／运行时参数恢复也可能因后续编辑冲突而停止。外部端口、应用认证、真实封禁、通知送达、业务恢复和性能提升不能仅靠本机检查证明，报告会保留待验证状态。

## 高级入口和测试边界

自定义问答仍保留在 `sudo vps-guard wizard`；高级分步、验收与恢复见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。可选 Netcatty 片段见 [netcatty/README.md](netcatty/README.md)。

单元测试使用临时文件系统和模拟命令，不修改开发电脑或 CI 主机的 SSH、防火墙、账号与内核队列。Linux CI 还验证无 Token 的固定提交下载。**真实 VPS 的 SSH 迁移、发行版服务与回滚仍需实机试跑**，见 [docs/TESTING.md](docs/TESTING.md)。

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_release.py
sudo bash install.sh
sudo vps-guard auto
```

## 依据

方案参考了 selfhosted 和 LowEndTalk 的实际运维讨论；涉及具体行为，以项目官方文档为准：

- [Docker 与 UFW 的交互](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- [自动安全更新与重启策略](https://ubuntu.com/server/docs/how-to/software/automatic-updates/)
- [OpenSSH 配置](https://man.openbsd.org/sshd_config)
- [Linux TCP 参数](https://docs.kernel.org/networking/ip-sysctl.html)
- [fq 队列](https://man7.org/linux/man-pages/man8/tc-fq.8.html)
