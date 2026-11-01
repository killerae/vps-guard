# VPS Guard

面向单台 VPS 的交互式加固向导。输入一条命令，选择跳过的项目、提供公钥和业务端口，工具自动按顺序部署。以后输入 `sudo vps-guard` 打开菜单，不依赖 Ansible、Skill 或大模型。

当前版本：0.2.0。支持 systemd 的 Debian／Ubuntu，Python 3.10+。单元测试和 Linux CI 不等于真实 VPS 的完整迁移测试，请先在可救援的测试机试用，记录见 [docs/TESTING.md](docs/TESTING.md)。

## 第一次使用

保留原 SSH 会话，并实际测试服务商网页控制台／Rescue。在 VPS 的 SSH 终端粘贴：

```bash
bash -c 'u=https://raw.githubusercontent.com/killerae/vps-guard/main/bootstrap.sh; f=$(mktemp) && (curl -fsSL "$u" -o "$f" || wget -qO "$f" "$u") && bash "$f"; r=$?; rm -f -- "$f"; exit "$r"'
```

需要 curl 或 wget 至少一个可用。入口先完整下载，下载成功后才执行；它再下载固定提交的工具包，核对固定清单哈希与逐文件哈希，然后安装并立即进入向导。下载不需要 GitHub Token，也不会要求你提供私钥。

首次入口来自本仓库 main，和任何在线安装器一样，需要信任仓库维护者与 HTTPS。后续工具包固定在已检查的提交，更新 main 不会悄悄替换本入口绑定的工具包。要完全固定入口，可将命令中的 main 改为你已审阅的 bootstrap 提交 SHA。

重复运行同版本入口会继续已安装向导。已有旧版运行记录时停止自动覆盖，避免破坏待恢复事务；升级前先完成／恢复旧变更。

只下载校验、暂不安装时，先下载 bootstrap.sh，再执行 `bash bootstrap.sh --download-only 一个尚不存在的目录`。该模式不提权、不装软件、不运行下载的程序。

向导会集中询问：

- 跳过哪些默认项目：系统更新、SSH 迁移、防火墙与 Fail2ban、BBR＋fq／TCP、日志与维护。
- 运维账号、公钥及允许的业务端口；私钥留在本机。
- 是否新建 Swap、是否配置异地备份。
- 可选的带宽／RTT 数据；不知道就保留 TCP 缓冲区原值。

Tailscale 不自动安装。端口不明时可跳过防火墙，未提供公钥时可跳过 SSH。已有 Docker／复杂防火墙／复杂队列会暂停自动处理。跳过系统更新时仍会按需安装所选模块必需的依赖。

首次入口会按需安装 Python 和下载工具。系统 Python 低于 3.10 时停止，不替换系统 Python；不自动整机重启。Netcatty 片段为可选入口，直接使用终端即可完成。

## SSH 迁移和执行顺序

| 步骤 | 向导动作／你需要做的事 |
| --- | --- |
| 1 | 自动检查，集中选择项目和填写差异信息 |
| 2 | 系统更新与依赖、可选 Swap |
| 3 | 准备运维账号、公钥和 sudo；保留原 SSH 登录方式 |
| 4 | 新建运维账号的独立密钥连接，执行 `sudo vps-guard continue` |
| 5 | 自动部署所选 BBR＋fq／TCP、防火墙、SSH；SSH 最后应用 |
| 6 | 提示完成后，再建全新的管理连接，执行同一句 `sudo vps-guard continue` |
| 7 | 验证通过后取消定时恢复，自动继续维护、可选备份及验收报告 |

两次 continue 都不需要变更编号。原向导窗口会自动继续；如果已经断开，后续在当前连接续跑。

优先核对服务器 root 归属的 sshd 日志中的账号、源地址／端口、公钥指纹和时间；日志不足时会明确要求输入 KEY／NEW。Netcatty 须建立新的 SSH 传输，单纯在旧连接里新开终端不算新连接。没有选择 SSH 迁移时，跳过第一次账号验证。

## 后续使用

```bash
sudo vps-guard
sudo vps-guard wizard
sudo vps-guard audit
sudo vps-guard verify
sudo vps-guard pending
```

断开或暂停后用 wizard 续跑，已完成阶段不重复执行。未完成的关键事务先检查状态，必要时恢复后再继续。重新选择项目用 `sudo vps-guard wizard --restart`；有待确认变更时禁止重开。

向导报告：`/var/lib/vps-guard/wizard-report.json`。未选模块显示 skipped；外部 IPv4／IPv6 可达性、业务认证、通知、恢复和性能效果仍需独立验收。高级分步命令见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。可选 Netcatty 片段见 [netcatty/README.md](netcatty/README.md)。

## 默认策略和恢复边界

- 保留实际 SSH 端口，采用普通运维账号＋密钥，验证后关闭 root／密码 SSH。
- 网络、防火墙、SSH 处于同一个限时恢复事务，SSH 最后应用。
- 新向导默认验证窗口 10 分钟；已有配置保留原值。
- BBR 使用当前内核的实现，实际出口队列采用 fq；不自动更换内核。
- TCP 使用保守基线，有可靠带宽／RTT 时再适配缓冲区；不保证所有线路提速。
- Swap 按需，已有 Swap 保留；首版新建仅支持 ext4／xfs。
- 保留已有公钥、服务和 UFW 放行规则，需自行审阅额外开放。
- 自动安全更新、日志容量和健康检查按所选项目执行；异地备份需提供目的地及凭据。

定时恢复依赖 systemd、机器在线及可恢复的旧配置，不能代替服务商救援。**待确认期间不要重启或同时修改相同配置。** 第三方改动可能阻止恢复，以免覆盖新配置。软件升级、账号、组成员及密码操作不会自动逆转；恢复不会删除账号数据。

## 配置与凭据

配置在 `/etc/vps-guard/config.json`，状态在 `/var/lib/vps-guard`。均在 VPS 本地由 root 管理；实际配置不上传 GitHub。示例见 [config.example.json](config.example.json)。

运维账号使用本地 sudo 密码，access 阶段必要时提示设置；SSH 密码登录随后关闭。备份恢复密码及访问凭据保存为 root 专用文件，恢复密码需另存于 VPS 外。env 按 KEY=value 读取，不执行 Shell 展开。仓库仅包含示例和程序，不应提交实际主机地址、私钥或 Token。

## 开发和手动安装

```bash
python3 -m unittest discover -s tests -v
python3 tools/build_release.py
sudo bash install.sh
sudo vps-guard wizard
```

发布包及 SHA-256 在 dist/。手动安装须先完整下载并核对可信发布版本；包内清单用于完整性校验，不能独立证明发布者身份。安装器只复制工具，向导经确认后才部署项目。
