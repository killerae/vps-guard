# Netcatty 快捷片段

首次直接使用仓库 README 的一键命令即可，不要求导入片段。安装后也可以输入 `sudo vps-guard` 打开菜单。

可选导入：打开 Netcatty 的 Snippets／快捷片段管理，导入 snippets.json。包不包含主机、身份或凭据，使用官方 SnippetTransfer 的 kind=netcatty.snippets、version=2 格式。全部片段设置 noAutoRun，手动核对当前机器并回车执行；不绑定全部主机，不广播，不设置连接后自动运行。

## 向导模式

- “开始／继续加固向导”：集中选择项目，按提示部署。
- “向导继续／新连接确认”：`sudo vps-guard continue`。账号准备后在新运维账号的密钥连接执行；部署完成提示后，再新建独立管理连接执行一次。原向导自动继续，不用变更编号。

sudo 可能不保留 SSH_CONNECTION，工具会尝试从父进程环境读取。无法识别时停止确认。Netcatty 如复用了同一 SSH 传输，需要断开后另建连接；只新开终端标签不足以验证。

## 高级分步模式

保留 apply access／confirm-login、各模块 apply 及 confirm 编号命令，适合手工控制单个阶段。向导中按 continue 提示操作即可。

“恢复指定变更”要求填写编号，恢复本轮工具管理的文件和运行参数；后续编辑冲突时停止，使用保留连接或服务商控制台检查。

一键入口完整下载后才执行，随后核对固定提交的工具包；手动下载也可进入已验证的包目录运行“安装当前目录工具包”。

格式依据：

- https://netcatty.app/en/docs/snippets/
- https://github.com/binaricat/Netcatty/blob/main/domain/snippetTransfer.ts
- https://github.com/binaricat/Netcatty/blob/main/domain/snippetTargets.ts
