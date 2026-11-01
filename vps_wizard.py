"""Interactive orchestration. No operation lock is held while waiting for a new SSH login."""
from __future__ import annotations

import contextlib
import copy
import getpass
import io
import json
import os
from pathlib import Path
import time

import vps_guard as vg

WIZARD_STATE = vg.STATE + "/wizard.json"
PROJECTS = {
    "1": ("baseline", "系统更新、依赖、时间同步"),
    "2": ("ssh", "运维账号、公钥、SSH 安全迁移"),
    "3": ("firewall", "防火墙与 SSH 防爆破"),
    "4": ("network", "BBR＋fq 和 TCP 调优"),
    "5": ("maintenance", "日志、安全更新和健康检查"),
}


def yes(prompt, default=False):
    suffix = " [Y/n]：" if default else " [y/N]："
    while True:
        answer = input(prompt + suffix).strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes", "是"):
            return True
        if answer in ("n", "no", "否"):
            return False
        print("请输入 y 或 n，或直接回车采用默认选项。")


def selected_projects(excluded):
    excluded = {x.strip() for x in excluded.replace("，", ",").split(",") if x.strip()}
    if not excluded.issubset(PROJECTS):
        raise vg.GuardError("项目编号应为 1..5；多个编号用逗号隔开")
    return [item[0] for number, item in PROJECTS.items() if number not in excluded]


def parse_ports(value):
    value = value.strip()
    if not value:
        return None
    if value.lower() in ("none", "无", "没有"):
        return []
    import re
    ports = []
    for item in value.replace("，", ",").split(","):
        match = re.fullmatch(r"\s*(\d+)/(tcp|udp)\s*", item)
        if not match or not 1 <= int(match.group(1)) <= 65535:
            raise vg.GuardError("端口格式如 443/tcp,8443/udp；不能确定时先跳过防火墙")
        ports.append({"port": int(match.group(1)), "protocol": match.group(2), "source": "any"})
    return ports


class Wizard:
    def __init__(self, guard):
        self.g = guard
        self.secret_files = {}

    def state(self):
        raw = self.g.read(WIZARD_STATE)
        if not raw:
            return None
        state = json.loads(raw)
        if state.get("schema") != 1:
            raise vg.GuardError("向导状态版本不兼容，请保留记录并人工检查")
        return state

    def save(self, state):
        state["updated_at"] = vg.utc()
        self.g.atomic(WIZARD_STATE, json.dumps(state, ensure_ascii=False, indent=2))

    def run_stage(self, state, stage):
        if stage in state["completed"]:
            return
        state["active_stage"] = stage
        self.save(state)

        with self.g.lock():
            self.g.apply(stage)
        state["completed"].append(stage)
        self.save(state)

    def apply_critical(self, stages, on_started):
        return self.g.apply_critical(stages, on_started=on_started)

    def critical_stages(self, state):
        return [x for x in ("network", "firewall", "ssh") if x in state["selected"]]

    def collect(self):
        self.g.preflight()
        facts = self.g.audit()
        print("\nVPS Guard 加固向导 " + vg.VERSION)
        print("主机：" + facts["hostname"] + "；系统：" + str(facts["os"].get("PRETTY_NAME")))
        ram = facts["memory"].get("MemTotal", 0)
        print(f"内存约 {ram // 1024**2} MiB；当前公网 SSH 端口将保留。")
        print("现有监听端口：\n" + facts["listeners"])
        print("\n默认项目：")
        for number, (_, label) in PROJECTS.items():
            print(number + ". " + label)
        selected = selected_projects(input("不执行哪些项目？填编号如 1,5；回车保留全部默认项目："))
        if not selected and not yes("默认项目全部跳过，仍要配置可选项目吗"):
            raise vg.GuardError("没有选择部署项目")
        exists = self.g.fs(vg.CONFIG).exists()
        c = self.g.config() if exists else copy.deepcopy(vg.DEFAULTS)
        if not exists:
            c["rollback_minutes"] = 10
        state = {"schema": 1, "created_at": vg.utc(), "phase": "prepare", "selected": selected,
                 "completed": [], "skipped": [], "last_error": None, "active_stage": None}
        if not c["provider_console_verified"]:
            c["provider_console_verified"] = yes("你已实际测试服务商网页控制台／Rescue 可以使用吗")
        if not c["provider_console_verified"]:
            print("尚未验证救援入口，本次只保留检查结果，等待验证后再部署。")
            self.g.atomic(vg.CONFIG, json.dumps(c, ensure_ascii=False, indent=2))
            return None
        if "ssh" in selected:
            if not exists or yes("需要修改运维账号或公钥吗"):
                c["admin_user"] = input(f"运维账号 [{c['admin_user']}]：").strip() or c["admin_user"]
                print("提供客户端公钥；私钥留在本机。已有正确公钥可直接回车保留。")
                key = input("粘贴一行 ssh-ed25519 等公钥：").strip()
                if key:
                    c["admin_public_keys"] = [key]
            if not c["admin_public_keys"]:
                if yes("没有提供公钥，暂时跳过 SSH 迁移吗", True):
                    selected.remove("ssh")
                    state["skipped"].append({"stage": "ssh", "reason": "尚未提供管理公钥"})
                else:
                    raise vg.GuardError("需要先提供公钥；原 SSH 设置保持原状")
        if "firewall" in selected and facts.get("docker_ports"):
            if yes("检测到运行中的 Docker，自动防火墙暂不覆盖此场景；本轮先跳过防火墙吗", True):
                selected.remove("firewall")
                state["skipped"].append({"stage": "firewall", "reason": "运行中的 Docker 需要单独审阅"})
            else:
                raise vg.GuardError("请先处理 Docker 的实际端口与防火墙路径")
        if "firewall" in selected:
            if not c["business_ports_confirmed"] or yes("需要修改公网业务端口清单吗"):
                ports = parse_ports(input("允许的公网业务端口，如 443/tcp,8443/udp；无业务填 none；未知直接回车："))
                if ports is None:
                    if not yes("端口尚未确定，先跳过防火墙吗", True):
                        raise vg.GuardError("请先确认业务端口")
                    selected.remove("firewall")
                    state["skipped"].append({"stage": "firewall", "reason": "业务端口未确认"})
                else:
                    c["business_ports"] = ports
                    c["business_ports_confirmed"] = True
        if "network" in selected:
            print("BBR＋fq 和 TCP 使用保守基线；没有带宽、RTT 数据时保留缓冲区现值。")
            if yes("现在提供明确的带宽目标和 RTT 吗"):
                try:
                    c["network"]["target_bandwidth_mbps"] = float(input("带宽目标 Mbps："))
                    c["network"]["representative_rtt_ms"] = float(input("代表性 RTT 毫秒："))
                except ValueError:
                    raise vg.GuardError("带宽和 RTT 必须为数字") from None
        if yes("需要评估新建 Swap 吗（已有 Swap 会保留）"):
            try:
                c["swap_mib"] = int(input("希望新建的大小 MiB [1024]：").strip() or "1024")
            except ValueError:
                raise vg.GuardError("Swap 大小必须为整数 MiB") from None
            selected.append("swap")
        if yes("本次接入异地备份吗（需要已有目的地和凭据）", c["backup"]["enabled"]):
            self.collect_backup(c)
            selected.append("backup")
        else:
            state["skipped"].append({"stage": "backup", "reason": "本轮未选择接入异地备份"})
        if not selected:
            raise vg.GuardError("本轮没有选择部署项目")
        vg.validate_config(c)
        print("\n本轮项目：" + ", ".join(selected))
        print(f"SSH 管理账号：{c['admin_user']}；验证窗口：{c['rollback_minutes']} 分钟。")
        print("Tailscale 不自动执行；未知容器／防火墙／队列冲突将暂停。")
        if "baseline" not in selected:
            print("已跳过系统升级；仍会按需安装所选模块必需的软件包。")
        if not yes("确认开始部署所选项目吗"):
            raise vg.GuardError("已取消，尚未执行加固阶段")
        for path, secret in self.secret_files.items():
            self.g.atomic(path, secret)
        self.g.atomic(vg.CONFIG, json.dumps(c, ensure_ascii=False, indent=2) + "\n")
        state["selected"] = selected
        state["config_digest"] = vg.sha(json.dumps(c, sort_keys=True).encode())
        self.save(state)
        return state

    def collect_backup(self, c):
        backup = c["backup"]
        backup["enabled"] = True
        if self.g.fs(backup["env_file"]).exists() and yes("沿用已配置的备份凭据吗", True):
            self.g.protected_env(backup["env_file"])
            return
        repository = input("异地 restic 仓库地址（s3:／sftp:／rest: 等）：").strip()
        if not repository.startswith(("s3:", "sftp:", "rest:", "b2:", "azure:", "gs:", "rclone:")):
            raise vg.GuardError("请提供支持的异地仓库地址")
        password = getpass.getpass("备份恢复密码（不回显，请在 VPS 外另存）：")
        if not password or password != getpass.getpass("再次输入恢复密码："):
            raise vg.GuardError("恢复密码为空或不一致")
        password_path = "/etc/vps-guard/restic-password"
        if self.g.fs(password_path).exists():
            raise vg.GuardError("已有恢复密码文件，为避免覆盖请在高级配置中处理")
        lines = ["RESTIC_REPOSITORY=" + repository, "RESTIC_PASSWORD_FILE=" + password_path]
        if repository.startswith("s3:"):
            access = getpass.getpass("S3 Access Key（不回显；使用实例身份可留空）：")
            secret = getpass.getpass("S3 Secret Key（不回显；使用实例身份可留空）：")
            if access or secret:
                lines += ["AWS_ACCESS_KEY_ID=" + access, "AWS_SECRET_ACCESS_KEY=" + secret]
        if any("\n" in line or "\r" in line for line in lines):
            raise vg.GuardError("备份凭据不能包含换行")
        paths = input("备份源目录，逗号分隔 [/etc]：").strip()
        if paths:
            backup["paths"] = [x.strip() for x in paths.split(",")]
        vg.validate_config(c)
        self.secret_files[password_path] = password + "\n"
        self.secret_files[backup["env_file"]] = "\n".join(lines) + "\n"
        print("确认开始后，恢复密码和凭据将保存为本机 root 专用文件，不会上传 GitHub。")

    def check_state(self, state):
        digest = vg.sha(json.dumps(self.g.config(), sort_keys=True).encode())
        if state["config_digest"] != digest:
            raise vg.GuardError("配置已在向导外改变；请先审阅状态与计划，不能直接继续旧流程")

    def wait_for(self, phase):
        while True:
            state = self.state()
            if state["phase"] != phase:
                return state
            if phase == "await_confirmation":
                self.g.load_tx(state["transaction"])
                status = self.g.tx["status"]
                if status in ("rolled_back", "rollback_failed"):
                    raise vg.GuardError("关键变更已到期恢复或恢复未完整成功；请检查保留会话与记录")
                if time.time() > self.g.tx["deadline"] + 60:
                    raise vg.GuardError("恢复窗口已过期，请检查 systemd 恢复任务")
            time.sleep(1)

    def prepare_backup(self, state):
        if "backup" not in state["selected"] or "backup" in state["completed"]:
            return
        with self.g.lock():
            self.g.run("apt-get", "install", "-y", "restic", interactive=True, timeout=600)
            try:
                self.g.restic("snapshots", "--json")
            except vg.GuardError:
                if not yes("仓库尚未连接成功；确认这是新的空仓库，需要初始化吗"):
                    raise vg.GuardError("备份接入已暂停，请检查目的地／凭据")
                self.g.restic("init")
        self.run_stage(state, "backup")
        if yes("现在运行首次备份吗", True):
            with self.g.lock():
                self.g.backup_run()
            state["completed"].append("backup-run")
            self.save(state)
        if yes("现在做文件恢复测试吗（会下载数据并占用磁盘）"):
            with self.g.lock():
                self.g.backup_restore_test()
            state["completed"].append("backup-restore-test")
            self.save(state)

    def drive(self, state):
        self.check_state(state)
        selected = state["selected"]
        if state["phase"] == "prepare":
            if "baseline" not in selected and "dependencies" not in state["completed"]:
                packages = {"ca-certificates"}
                for stage, names in {
                    "ssh": ("sudo", "openssh-server", "adduser"),
                    "firewall": ("ufw", "fail2ban", "python3-systemd"),
                    "network": ("iproute2", "kmod", "procps"),
                    "maintenance": ("unattended-upgrades", "logrotate"),
                }.items():
                    if stage in selected:
                        packages.update(names)
                missing = [p for p in sorted(packages) if self.g.out("dpkg-query", "-W", "-f=${Status}", p) != "install ok installed"]
                if missing:
                    with self.g.lock():
                        self.g.run("apt-get", "update", interactive=True, timeout=600)
                        self.g.run("apt-get", "install", "-y", *missing, interactive=True, timeout=1800)
                state["completed"].append("dependencies")
                self.save(state)
            for stage in ("baseline", "swap"):
                if stage in selected:
                    self.run_stage(state, stage)
            if "ssh" in selected:
                self.run_stage(state, "access")
                state["phase"] = "await_login"
                self.save(state)
        if state["phase"] == "await_login":
            print("\n现在保留本窗口，在 Netcatty 新建运维账号的密钥连接。")
            print("在新连接只需执行：sudo vps-guard continue")
            print("验证成功后，本窗口会自动接着部署。Ctrl+C 可暂停，进度已保存。")
            state = self.wait_for("await_login")
        if state["phase"] in ("prepare", "critical"):
            critical = self.critical_stages(state)
            if critical:
                state["phase"] = "critical"
                state["active_stage"] = "critical"
                self.save(state)
                def on_started(ident):
                    state["transaction"] = ident
                    state["phase"] = "critical_running"
                    self.save(state)
                with self.g.lock():
                    ident = self.apply_critical(critical, on_started)
                state["phase"] = "await_confirmation"
                state["transaction"] = ident
                self.save(state)
        if state["phase"] == "await_confirmation":
            print("\n所选网络／SSH 项目已部署，原窗口继续保留。")
            print("请在此提示后再建立一次新的管理连接，执行同一条命令：")
            print("sudo vps-guard continue")
            state = self.wait_for("await_confirmation")
        if state["phase"] in ("prepare", "maintenance"):
            state["phase"] = "maintenance"
            self.save(state)
            if "maintenance" in selected:
                self.run_stage(state, "maintenance")
            self.prepare_backup(state)
            state["phase"] = "done"
            state["finished_at"] = vg.utc()
            self.save(state)
        if state["phase"] == "done":
            return self.report(state)
        return 0

    def report(self, state):
        print("\n选定项目已部署。正在生成验收报告；未选项目会明确列为跳过。")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = self.g.verify(scope=state["selected"])
        report = buffer.getvalue()
        self.g.atomic(vg.STATE + "/wizard-report.json", report)
        data = json.loads(report)
        for item in data["checks"]:
            print(f"{item['status']:14} {item['name']}：{item['detail']}")
        print("报告：/var/lib/vps-guard/wizard-report.json")
        print("重启持久化、外部端口、业务认证及性能改善需按报告完成验证。")
        print("以后输入 sudo vps-guard 即可进入工具菜单。")
        return 2 if code == 2 else 0

    def refresh_transaction(self, state):
        phase = state.get("resume_phase") if state["phase"] == "paused" else state["phase"]
        if phase not in ("critical_running", "await_confirmation") or not state.get("transaction"):
            return state
        with self.g.lock():
            self.g.load_tx(state["transaction"])
            tx = self.g.tx
            if tx["status"] == "committed":
                state["phase"] = "maintenance"
                for stage in tx.get("components", []):
                    if stage not in state["completed"]:
                        state["completed"].append(stage)
            elif tx["status"] == "awaiting_confirmation" and tx.get("ready_at"):
                state["phase"] = "await_confirmation"
            elif tx["status"] in ("running", "awaiting_confirmation"):
                self.g.rollback(tx["id"], automatic=True)
                state.update(phase="paused", resume_phase="critical", last_error="前次部署中断，已恢复关键配置")
            elif tx["status"] == "rolled_back":
                state.update(phase="paused", resume_phase="critical", last_error="前次关键配置已恢复，请检查原因再继续")
            else:
                raise vg.GuardError("前次恢复未完成，请通过保留会话／控制台检查记录")
        self.save(state)
        return state

    def run(self, restart=False):
        self.g.preflight()
        with self.g.lock("wizard.lock"):
            state = self.state()
            if restart and state:
                if self.g.pending():
                    raise vg.GuardError("先确认或恢复待处理变更，才能重新开始向导")
                self.g.atomic(vg.STATE + "/wizard-history/" + str(time.time_ns()) + ".json", json.dumps(state))
                state = None
            if state:
                state = self.refresh_transaction(state)
            if state and state["phase"] == "done":
                if not yes("上一次向导已完成，重新选择项目开始新一轮吗"):
                    return self.drive(state)
                state = None
            if state and state.get("phase") == "paused":
                print("上次暂停原因：" + str(state.get("last_error")))
                if not yes("检查问题后，继续已保存的流程吗", True):
                    if not yes("改为重新选择项目并开始新一轮吗"):
                        return 0
                    if self.g.pending():
                        raise vg.GuardError("先处理等待确认的变更")
                    state = None
                else:
                    state["phase"] = state["resume_phase"]
                    self.save(state)
            if state is None:
                state = self.collect()
                if state is None:
                    return 0
            try:
                return self.drive(state)
            except (vg.GuardError, OSError, ValueError) as error:
                current = self.state() or state
                current["resume_phase"] = current["phase"]
                current["phase"] = "paused"
                current["last_error"] = str(error)
                self.save(current)
                raise

    def continue_from_login(self):
        with self.g.lock():
            state = self.state()
            if state is None:
                raise vg.GuardError("没有待继续的向导，请先运行 sudo vps-guard")
            self.check_state(state)
            phase = state["phase"]
            if phase == "paused":
                phase = state["resume_phase"]
            if phase == "critical_running":
                self.g.load_tx(state["transaction"])
                if self.g.tx["status"] == "awaiting_confirmation" and self.g.tx.get("ready_at"):
                    phase = "await_confirmation"
            if phase == "await_login":
                self.g.confirm_login(automatic=True)
                state["phase"] = "critical"
            elif phase == "await_confirmation":
                self.g.confirm(state["transaction"])
                self.g.load_tx(state["transaction"])
                for item in self.g.tx.get("components", []):
                    if item not in state["completed"]:
                        state["completed"].append(item)
                state["phase"] = "maintenance"
            elif phase == "done":
                print("本轮已完成；使用 sudo vps-guard 查看菜单。")
                return 0
            else:
                raise vg.GuardError("当前阶段不等待新连接验证；请回到原窗口")
            state["last_error"] = None
            self.save(state)
        try:
            with self.g.lock("wizard.lock"):
                pass
        except vg.GuardError:
            print("验证完成，原窗口将自动继续。")
            return 0
        print("原窗口已退出，将在当前连接继续已保存的流程。")
        return self.run()
