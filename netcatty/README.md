# Netcatty 快捷片段

1. 打开 Netcatty 的 Snippets／快捷片段管理。
2. 使用其导入功能选择 snippets.json；导入是片段包，不包含主机、身份或任何凭据。
3. 在已经连接的单台测试机终端中选择片段。
4. 默认只将命令填入终端；核对目标机器和命令后回车执行。

包采用官方 SnippetTransfer 的 kind=netcatty.snippets、version=2 格式；使用 label、command、package、description 和 noAutoRun 字段。不设置开机或连接触发，不绑定“所有主机”，不使用广播模式。当前版本在活动终端使用未绑定主机的片段；如果你的版本要求目标绑定，手动只绑定测试主机。

先在远端安装工具，再调用片段。片段本身不下载或更新远端代码；同一套入口可以长期复用。

## SSH 确认怎么用

apply access 后，新建普通运维账号的密钥连接，运行“确认新账号密钥登录”。

apply ssh／firewall／network 后，原会话会输出变更编号。新建一条独立 SSH 连接，运行“确认当前变更”，按提示填写变更编号。不能直接在原会话确认。

sudo 可能不保留 SSH_CONNECTION；工具会尝试从父进程环境读取该字段。无法可靠识别连接时停止确认，不自动绕过。Netcatty 如果复用了同一个 SSH 传输，需要重新连接建立不同的客户端端口。

## 安装入口

首次安装请使用已经下载并校验的发布包，进入其解压目录后运行“安装当前目录工具包”。不把原始下载地址与 sudo 执行串成一条远程脚本命令。

## 恢复入口

“恢复指定变更”会提示填写编号，随后恢复本次工具管理的文件和运行参数。已被后续编辑的文件将阻止恢复；通过保留连接或服务商控制台人工检查，不使用强制覆盖。

格式依据：
- https://netcatty.app/en/docs/snippets/
- https://github.com/binaricat/Netcatty/blob/main/domain/snippetTransfer.ts
- https://github.com/binaricat/Netcatty/blob/main/domain/snippetTargets.ts
