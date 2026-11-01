# 操作、验收和恢复

## 1. 入口和配置

工具入口为 /usr/local/bin/vps-guard。首次运行 setup 填写账号、公钥、控制台验证和业务端口。已有配置不会被 setup 覆盖；使用 sudoedit /etc/vps-guard/config.json 修改，随后运行 plan。

setup 中的控制台确认是操作人已实际测试的记录，程序不会替你验证服务商网页。不能为了继续执行把未验证事项直接写成 true。

业务端口示例：

```json
{
  "business_ports_confirmed": true,
  "business_ports": [
    {"port": 443, "protocol": "tcp", "source": "any"},
    {"port": 8443, "protocol": "udp", "source": "any"}
  ]
}
```

这些字段需合并到实际配置中，不替换整份文件。无业务时业务列表为空，并在确认后将 business_ports_confirmed 设为 true。ssh_port 为 null 时保留 sshd 的当前端口，首版不自动改端口。

## 2. 更新与时间

```bash
sudo vps-guard apply baseline
```

先检查包管理状态，再更新、按配置升级和安装依赖，设置时区与时间同步。包更新可能重启服务；在新机未上线或维护窗口执行。upgrade_packages=false 可跳过本次系统升级，后续需自行补齐更新。

不自动执行整机重启。若系统提示需要重启，在没有待确认变更且救援可用时自行安排。软件升级不提供一键包级降级。

## 3. Swap

默认 swap_mib=null，保留原配置。决定需要新建时填写整数 MiB，再运行：

```bash
sudo vps-guard apply swap
```

首版只在没有已启用 Swap 且根文件系统为 ext4／xfs 时新建 /swapfile-vps-guard。已有 Swap 保留；其他文件系统单独处理。恢复时要求内存有足够余量，避免 swapoff 导致内存压力。

## 4. 账号与 SSH

```bash
sudo vps-guard apply access
```

创建或检查 ops，保留已有公钥，追加指定公钥，必要时交互设置 sudo 密码。此时尚未关闭初始 SSH 登录方式。

在 Netcatty 建立 ops 的新连接，认证方式明确选密钥，运行：

```bash
sudo vps-guard confirm-login
```

只有确认实际使用了密钥，才输入 KEY。该记录是防止误操作的流程门槛，不是对操作人的密码学证明。

回到保留的原会话执行：

```bash
sudo vps-guard apply ssh
```

工具启动恢复计时器，写入专用 SSH 片段，检查最终配置后重载。默认保留端口、SFTP 和 TCP 端口转发。非标准 Include 布局或冲突的 Match 设置会阻止应用。

再新建一条 ops 密钥连接，按输出的实际编号确认：

```text
sudo vps-guard confirm <实际变更编号>
```

确认后，定时恢复取消。另从独立测试连接检查 root 和密码认证被拒绝，避免在唯一管理来源反复失败触发封禁。

```bash
sudo vps-guard attest auth_rejection
```

## 5. 防火墙与 Fail2ban

```bash
sudo vps-guard apply firewall
```

要求已确认业务端口、UFW IPv6 配置正常，且没有运行中的 Docker 或其他防火墙冲突。先放行 SSH 和业务，再设置默认拒绝入站、允许正常出站，配置实际 SSH 端口对应的 Fail2ban jail。

现有 UFW 放行不会自动删除，所以需要审阅额外放行。已有自定义防火墙、容器端口或转发场景应依据 audit 输出单独处理，不能把工具停止当作加固完成。

新连接运行 confirm 后，从外部验证公网 IPv4／IPv6 与云防火墙。使用独立测试来源验证 Fail2ban 检测与封禁，确认唯一管理入口安全，再记录：

```bash
sudo vps-guard attest external_reachability
sudo vps-guard attest ban_test
```

## 6. 应用审阅

本工具不识别所有应用的业务认证、TLS 或数据库配置。根据实际软件检查：专用运行账号、后台绑定、认证、TLS、容器特权与挂载、Docker 组权限，以及必要的 systemd LimitNOFILE。修改后检查真实业务和进程限制。

```bash
sudo vps-guard attest application_review
```

## 7. BBR＋fq 与 TCP

```bash
sudo vps-guard apply network
```

固定目标：当前受维护内核提供的 bbr，实际出站队列或 mq 叶子为 fq。默认识别 IPv4／IPv6 路由；含隧道等路径时需明确填写 network.devices。复杂队列、过滤器或缺少内核支持会停止覆盖。

TCP 基线启用接收自动调节、窗口扩大、SACK、时间戳，以及按需 MTU 黑洞探测。默认不降低连接重试次数或修改连接超时，不设置通用大队列。

缓冲区输入：
- target_bandwidth_mbps、representative_rtt_ms：有可靠目标／测量时填写。
- tcp_buffer_max_bytes：可显式填写经过评估的候选上限。
- socket_buffer_max_bytes：应用主动设置 Socket 缓冲区时按需填写。

自动候选按 2 倍带宽时延积向上取整到 2 的幂，并限制在工具设定的单连接预算（内存的 1/16、最多 64 MiB）内。这是保守的工程起点，不是所有线路的最优值；总并发内存还需实际观察。输入不足时只应用 TCP 基线、保留缓冲区现值。原有更高上限不会被自动降低。

应用后新连接 confirm，再通过实际业务新连接及 ss -tin 检查算法。已有连接和监听器、容器命名空间、应用自定义算法可能不同，必要的服务重启在维护窗口进行。

本工具不自动测速和消耗套餐流量。人工进行同端点、相近条件下的正反向、单／多连接对比，记录吞吐、负载延迟、重传、CPU 和内存后：

```bash
sudo vps-guard attest performance
```

QUIC／Hysteria 2 的 UDP 缓冲区和应用流控单独评估；系统 TCP BBR 不替代用户态 QUIC 的拥塞控制。

## 8. 维护、通知与异地备份

```bash
sudo vps-guard apply maintenance
```

启用安全更新任务、日志容量限制和每小时本机健康检查。服务重启策略需要结合实际业务评估；自动整机重启保持关闭。Docker 日志容量需按容器配置。

要接入通知，创建 /etc/vps-guard/notify.env，root 所有、权限 600，填写接受 JSON text 消息的 HTTPS WEBHOOK_URL。健康检查存在告警时发送；它无法在服务器离线时自行通知，所以还需外部检测。实际送达及离线检测完成后记录 notifications 验收。

异地备份：
1. 准备受限的异地仓库和恢复密码。
2. 创建 /etc/vps-guard/backup.env 与恢复密码文件，均限制为 root 可读。
3. 在 config.json 中启用 backup，填写源目录和周期。数据库先准备一致性的导出或其他合适机制。
4. 新仓库需要初始化时，明确执行 backup-init；已有仓库跳过初始化。
5. 配置调度、执行首次备份与恢复。

```bash
sudo vps-guard backup-init
sudo vps-guard apply backup
sudo vps-guard backup-run
sudo vps-guard backup-restore-test
```

恢复测试将最新快照恢复到 /var/lib/vps-guard/restore-tests/ 下的独立目录，并检查仓库元数据。它证明文件可恢复；还需要实际验证业务启动和数据库一致性，再记录 service_restore。

默认不自动 prune 或删除远端快照。恢复密码必须另存，不能只保存在同一 VPS。

## 9. 验收与重启

```bash
sudo vps-guard verify
sudo vps-guard pending
```

verify 返回 0 表示已配置检查无失败／待人工项，2 表示存在失败，3 表示仍有待人工项。not_tested 单独列示，不能当作性能通过。人工 attest 与当前配置摘要绑定，配置变化后需要重新核实。

在 pending 没有等待确认的变更时，在维护窗口受控重启。重新通过密钥登录后再次执行 verify，确认实际配置、业务和定时任务仍正常。

## 10. 恢复

查看最近变更目录 /var/lib/vps-guard/runs/，选择需要恢复的实际编号：

```text
sudo vps-guard rollback <实际变更编号>
```

工具恢复原文件、运行时 TCP 参数及队列等本次管理的内容；仅删除 sysctl 配置文件不足以恢复运行值。遇到后续编辑冲突会停止，避免覆盖新配置。

定时恢复使用 systemd 瞬时任务；服务失败会重试。它依赖机器在线，跨重启不保证继续存在，不能替代服务商控制台。待确认期间不要重启。收到部分恢复失败提示时，保持原会话并使用控制台核对记录。

## 技术依据

- OpenSSH：https://man.openbsd.org/sshd_config
- Docker 端口与 UFW：https://docs.docker.com/engine/network/packet-filtering-firewalls/
- Linux TCP：https://docs.kernel.org/networking/ip-sysctl.html
- Linux qdisc：https://docs.kernel.org/admin-guide/sysctl/net.html
- BBR：https://github.com/google/bbr
- 自动更新：https://ubuntu.com/server/docs/how-to/software/automatic-updates/
- restic：https://restic.readthedocs.io/en/stable/010_introduction.html
