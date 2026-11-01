# Netcatty 快捷片段

首次执行仓库 README 的一键入口，自动安装并运行个人默认方案。以后输入 `sudo vps-guard` 打开菜单回车，或者运行“一键默认加固／续跑”片段即可；无需导入片段也能使用。

预设为 ops＋lu-admin 公钥＋免密 sudo。主机使用对应的私钥连接；私钥只存于本机。配置和密钥内容不会由本工具上传 GitHub。

## SSH 验证

准备账号后，按提示新建 ops 独立密钥连接，执行“继续／新连接确认”：`sudo vps-guard continue`。部署完成提示后，再新建一次独立管理连接执行同一句命令。原窗口自动继续，无需填写变更编号。

只新开终端标签但复用原 SSH 传输不满足验证条件。保留原窗口，10 分钟内完成部署后的新连接确认；等待期间不要重启。

## 报告与高级操作

“查看上次操作报告”对应 `sudo vps-guard report`。完整 JSON 在 /var/lib/vps-guard/last-report.json，可交给 AI 后续调整。

分步 apply、confirm-login、confirm 编号和 rollback 入口保留给高级操作；默认流程按 continue 提示即可。原有交互问答向导通过 `sudo vps-guard wizard` 进入。

全部片段使用官方 SnippetTransfer 的 kind=netcatty.snippets、version=2 格式，并设置 noAutoRun：手工核对目标机器后执行，不广播，不设置为连接后自动执行。导入包不含主机、身份或私钥。

格式依据：

- https://netcatty.app/en/docs/snippets/
- https://github.com/binaricat/Netcatty/blob/main/domain/snippetTransfer.ts
